from __future__ import annotations

import joblib
import pandas as pd

from src.core.config import Config


class Predictor:
    """Load persisted ML artefacts and enrich feature rows with predictions."""

    def __init__(self) -> None:
        if not Config.MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Trained model not found: {Config.MODEL_PATH}"
            )
        if not Config.FEATURE_PATH.exists():
            raise FileNotFoundError(
                f"Feature schema not found: {Config.FEATURE_PATH}"
            )

        self.model = joblib.load(Config.MODEL_PATH)
        self.feature_columns: list[str] = joblib.load(Config.FEATURE_PATH)

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add attack prediction and model confidence while preserving metadata.
        """
        missing = set(self.feature_columns).difference(df.columns)
        if missing:
            raise ValueError(
                "Prediction input is missing trained features: "
                + ", ".join(sorted(missing))
            )

        output = df.copy()
        X = (
            output.reindex(columns=self.feature_columns)
            .apply(pd.to_numeric, errors="coerce")
            .fillna(0)
        )

        output["prediction"] = self.model.predict(X)

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(X)
            output["confidence"] = probabilities.max(axis=1)
        else:
            output["confidence"] = 1.0

        return output
