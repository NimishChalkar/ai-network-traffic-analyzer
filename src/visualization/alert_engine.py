from __future__ import annotations

import hashlib

import pandas as pd

from src.visualization.severity import SeverityEngine


class AlertEngine:
    """
    Convert model predictions into enriched, deduplicated SOC alerts.

    Duplicate detections from the same source, destination and attack type are
    aggregated into a configurable time bucket to reduce alert spam.
    """

    def __init__(
        self,
        deduplication_seconds: int = 60,
        include_normal: bool = False,
    ) -> None:
        self.severity_engine = SeverityEngine()
        self.deduplication_seconds = deduplication_seconds
        self.include_normal = include_normal

    @staticmethod
    def _alert_id(src_ip: str, dst_ip: str, attack: str, bucket: str) -> str:
        raw = f"{src_ip}|{dst_ip}|{attack}|{bucket}".encode("utf-8")
        return hashlib.sha1(raw).hexdigest()[:12].upper()

    @staticmethod
    def _severity_from_score(score: float) -> str:
        if score >= 85:
            return "CRITICAL"
        if score >= 65:
            return "HIGH"
        if score >= 35:
            return "MEDIUM"
        return "LOW"

    def generate_alerts(self, df: pd.DataFrame) -> pd.DataFrame:
        """Build and deduplicate enriched alert records."""
        if "prediction" not in df.columns:
            raise ValueError("Prediction dataframe requires 'prediction'.")

        working = df.copy()
        if not self.include_normal:
            working = working[working["prediction"] != "normal"]

        output_columns = [
            "alert_id",
            "timestamp",
            "last_seen",
            "src_ip",
            "dst_ip",
            "attack",
            "severity",
            "risk_score",
            "confidence",
            "occurrences",
            "packet_count",
            "mitre",
        ]

        if working.empty:
            return pd.DataFrame(columns=output_columns)

        event_time = working.get(
            "window_start",
            pd.Series(pd.Timestamp.now(tz="UTC"), index=working.index),
        )
        working["event_time"] = pd.to_datetime(
            event_time,
            utc=True,
            errors="coerce",
        ).fillna(pd.Timestamp.now(tz="UTC"))

        working["src_ip"] = working.get("src_ip", "unknown").fillna("unknown")
        working["dst_ip"] = working.get("dst_ip", "unknown").fillna("unknown")
        working["confidence"] = pd.to_numeric(
            working.get("confidence", 1.0),
            errors="coerce",
        ).fillna(0.0)

        enriched_rows: list[dict] = []
        for row in working.itertuples(index=False):
            attack = str(row.prediction)
            metadata = self.severity_engine.evaluate(attack)
            confidence = float(row.confidence)

            # Confidence-adjusted risk preserves the attack baseline while
            # reducing priority for uncertain classifications.
            adjusted_score = round(
                float(metadata["score"]) * (0.50 + 0.50 * confidence),
                1,
            )

            enriched_rows.append(
                {
                    "event_time": row.event_time,
                    "src_ip": str(getattr(row, "src_ip", "unknown")),
                    "dst_ip": str(getattr(row, "dst_ip", "unknown")),
                    "attack": attack,
                    "risk_score": adjusted_score,
                    "confidence": confidence,
                    "packet_count": int(
                        getattr(row, "packet_count", 0)
                    ),
                    "mitre": metadata["mitre"],
                }
            )

        alerts = pd.DataFrame(enriched_rows)
        bucket_frequency = f"{self.deduplication_seconds}s"
        alerts["dedup_bucket"] = alerts["event_time"].dt.floor(
            bucket_frequency
        )

        grouped = (
            alerts.groupby(
                ["src_ip", "dst_ip", "attack", "dedup_bucket"],
                as_index=False,
            )
            .agg(
                timestamp=("event_time", "min"),
                last_seen=("event_time", "max"),
                risk_score=("risk_score", "max"),
                confidence=("confidence", "max"),
                occurrences=("attack", "size"),
                packet_count=("packet_count", "sum"),
                mitre=("mitre", "first"),
            )
        )

        grouped["severity"] = grouped["risk_score"].apply(
            self._severity_from_score
        )
        grouped["alert_id"] = grouped.apply(
            lambda row: self._alert_id(
                row["src_ip"],
                row["dst_ip"],
                row["attack"],
                row["dedup_bucket"].isoformat(),
            ),
            axis=1,
        )

        grouped["timestamp"] = grouped["timestamp"].dt.strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        grouped["last_seen"] = grouped["last_seen"].dt.strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        grouped["confidence"] = (grouped["confidence"] * 100).round(1)

        return (
            grouped[output_columns]
            .sort_values(
                ["risk_score", "timestamp"],
                ascending=[False, False],
            )
            .reset_index(drop=True)
        )

    @staticmethod
    def get_critical_alerts(alerts_df: pd.DataFrame) -> pd.DataFrame:
        """Return only alerts currently scored as critical."""
        return alerts_df[alerts_df["severity"] == "CRITICAL"]
