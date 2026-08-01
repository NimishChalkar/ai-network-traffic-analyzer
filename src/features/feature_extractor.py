from __future__ import annotations

import pandas as pd

from src.core.config import Config


class FeatureExtractor:
    """
    Convert packet rows into source-IP behavioural windows.

    Grouping by source IP and a fixed time window preserves scan, brute-force
    and flood behaviour. It also creates many ML samples from each PCAP rather
    than one aggregate row for the entire capture.
    """

    REQUIRED_COLUMNS = {
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packet_size",
        "is_syn",
        "is_rst",
    }

    def __init__(self, window_seconds: int = Config.WINDOW_SECONDS) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero.")
        self.window_seconds = window_seconds

    @staticmethod
    def _mode_or_default(series: pd.Series, default):
        """Return the most frequent non-null value or a safe default."""
        non_null = series.dropna()
        if non_null.empty:
            return default
        modes = non_null.mode()
        return modes.iloc[0] if not modes.empty else non_null.iloc[0]

    def extract(self, packets: pd.DataFrame) -> pd.DataFrame:
        """
        Produce one feature row per source IP per fixed time window.

        Metadata columns are retained for the dashboard but are excluded from
        model training through Config.FEATURE_COLUMNS.
        """
        if packets.empty:
            return pd.DataFrame()

        missing = self.REQUIRED_COLUMNS.difference(packets.columns)
        if missing:
            raise ValueError(
                "Packet dataframe is missing required columns: "
                + ", ".join(sorted(missing))
            )

        df = packets.copy()
        df["event_time"] = pd.to_datetime(
            df["timestamp"],
            unit="s",
            utc=True,
            errors="coerce",
        )
        df = df.dropna(subset=["event_time", "src_ip", "dst_ip"])
        df = df.sort_values("event_time")

        window_frequency = f"{self.window_seconds}s"
        df["window_start"] = df["event_time"].dt.floor(window_frequency)

        rows: list[dict] = []

        for (src_ip, window_start), group in df.groupby(
            ["src_ip", "window_start"],
            sort=True,
            observed=True,
        ):
            group = group.sort_values("event_time")
            packet_count = int(len(group))

            if packet_count == 0:
                continue

            first_seen = group["event_time"].iloc[0]
            last_seen = group["event_time"].iloc[-1]
            duration = max((last_seen - first_seen).total_seconds(), 0.0)
            safe_duration = max(duration, 1.0)

            interarrival = (
                group["event_time"]
                .diff()
                .dt.total_seconds()
                .dropna()
            )

            per_second_counts = (
                group.set_index("event_time")
                .resample("1s")
                .size()
            )

            syn_count = int(group["is_syn"].sum())
            rst_count = int(group["is_rst"].sum())
            ssh_mask = (group["src_port"] == 22) | (group["dst_port"] == 22)
            ssh_packet_count = int(ssh_mask.sum())

            rows.append(
                {
                    # Analyst/dashboard metadata
                    "window_start": window_start.isoformat(),
                    "window_end": last_seen.isoformat(),
                    "src_ip": str(src_ip),
                    "dst_ip": str(
                        self._mode_or_default(group["dst_ip"], "unknown")
                    ),
                    "src_port": int(
                        self._mode_or_default(group["src_port"], 0)
                    ),
                    "dst_port": int(
                        self._mode_or_default(group["dst_port"], 0)
                    ),
                    "protocol": str(
                        self._mode_or_default(group["protocol"], "OTHER")
                    ),

                    # Numeric model features
                    "packet_count": packet_count,
                    "avg_packet_size": float(group["packet_size"].mean()),
                    "std_packet_size": float(
                        group["packet_size"].std(ddof=0)
                    ),
                    "min_packet_size": int(group["packet_size"].min()),
                    "max_packet_size": int(group["packet_size"].max()),
                    "total_bytes": int(group["packet_size"].sum()),
                    "unique_destinations": int(group["dst_ip"].nunique()),
                    "unique_destination_ports": int(
                        group.loc[group["dst_port"] > 0, "dst_port"].nunique()
                    ),
                    "unique_source_ports": int(
                        group.loc[group["src_port"] > 0, "src_port"].nunique()
                    ),
                    "protocol_count": int(group["protocol"].nunique()),
                    "flow_duration": float(duration),
                    "packets_per_second": float(packet_count / safe_duration),
                    "syn_count": syn_count,
                    "syn_ratio": float(syn_count / packet_count),
                    "rst_count": rst_count,
                    "rst_ratio": float(rst_count / packet_count),
                    "ssh_packet_count": ssh_packet_count,
                    "ssh_ratio": float(ssh_packet_count / packet_count),
                    "avg_interarrival_time": float(
                        interarrival.mean() if not interarrival.empty else 0.0
                    ),
                    "std_interarrival_time": float(
                        interarrival.std(ddof=0)
                        if len(interarrival) > 1
                        else 0.0
                    ),
                    "max_packets_per_second": int(
                        per_second_counts.max()
                        if not per_second_counts.empty
                        else packet_count
                    ),
                }
            )

        features = pd.DataFrame(rows)

        # Replace any non-finite numeric values before ML training.
        for column in Config.FEATURE_COLUMNS:
            if column in features.columns:
                features[column] = (
                    pd.to_numeric(features[column], errors="coerce")
                    .fillna(0)
                    .replace([float("inf"), float("-inf")], 0)
                )

        return features
