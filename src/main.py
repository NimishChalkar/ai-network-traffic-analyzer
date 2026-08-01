import pandas as pd

from src.core.config import Config
from src.detection.predictor import Predictor
from src.visualization.alert_engine import AlertEngine
from src.visualization.timeline import TimelineEngine


def main() -> None:
    """Run inference, alert enrichment and timeline generation."""
    print("\n[+] SOC PIPELINE STARTING...\n")

    if not Config.DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {Config.DATASET_PATH}. "
            "Run the dataset builder first."
        )

    dataset = pd.read_csv(Config.DATASET_PATH)
    print(f"[+] Loaded dataset: {dataset.shape}")

    predictions = Predictor().predict(dataset)
    predictions.to_csv(Config.PREDICTIONS_PATH, index=False)
    print(f"[+] Predictions saved: {Config.PREDICTIONS_PATH}")

    alerts = AlertEngine().generate_alerts(predictions)
    alerts.to_csv(Config.ALERTS_PATH, index=False)
    print(f"[+] Deduplicated alerts saved: {Config.ALERTS_PATH}")

    timeline = TimelineEngine().build_timeline(alerts)
    timeline.to_csv(Config.TIMELINE_PATH, index=False)
    print(f"[+] Timeline saved: {Config.TIMELINE_PATH}")

    print("\n=== TOP ALERTS ===")
    print(alerts.head(10).to_string(index=False))

    print("\n[+] SOC PIPELINE COMPLETE\n")


if __name__ == "__main__":
    main()
