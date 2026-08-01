from __future__ import annotations

import pandas as pd


class TimelineEngine:
    """Build a chronological incident timeline from deduplicated alerts."""

    ATTACK_STAGES = {
        "nmap": "Discovery / Scanning",
        "hydra": "Credential Access",
        "dos": "Impact",
        "normal": "Baseline Activity",
    }

    def build_timeline(self, alerts_df: pd.DataFrame) -> pd.DataFrame:
        """Return alerts ordered by event time with incident-stage context."""
        if alerts_df.empty:
            output = alerts_df.copy()
            output["event_id"] = pd.Series(dtype="int64")
            output["incident_stage"] = pd.Series(dtype="object")
            return output

        timeline = alerts_df.copy()
        timeline["_sort_time"] = pd.to_datetime(
            timeline["timestamp"],
            utc=True,
            errors="coerce",
        )
        timeline = timeline.sort_values("_sort_time", ascending=True)
        timeline["event_id"] = range(1, len(timeline) + 1)
        timeline["incident_stage"] = timeline["attack"].map(
            self.ATTACK_STAGES
        ).fillna("Unknown Stage")

        return timeline.drop(columns=["_sort_time"]).reset_index(drop=True)
