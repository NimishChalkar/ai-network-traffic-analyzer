from pathlib import Path


class Config:
    """Central configuration for the network traffic analysis pipeline."""

    BASE_DIR = Path(__file__).resolve().parents[2]

    DATA_DIR = BASE_DIR / "data"
    RAW_DATA = DATA_DIR / "raw"
    PROCESSED_DATA = DATA_DIR / "processed"
    MODELS_DIR = DATA_DIR / "models"

    DATASET_PATH = PROCESSED_DATA / "dataset.csv"
    PREDICTIONS_PATH = PROCESSED_DATA / "predictions.csv"
    ALERTS_PATH = PROCESSED_DATA / "alerts.csv"
    TIMELINE_PATH = PROCESSED_DATA / "timeline.csv"
    FEATURE_IMPORTANCE_PATH = PROCESSED_DATA / "feature_importance.csv"
    CONFUSION_MATRIX_PATH = PROCESSED_DATA / "confusion_matrix.png"
    CLASSIFICATION_REPORT_PATH = PROCESSED_DATA / "classification_report.txt"

    MODEL_PATH = MODELS_DIR / "attack_classifier.pkl"
    FEATURE_PATH = MODELS_DIR / "feature_columns.pkl"

    RANDOM_STATE = 42
    TEST_SIZE = 0.20

    # Each source IP creates one behavioural sample per time window.
    WINDOW_SECONDS = 10

    # Numeric columns used by the model. Metadata such as IP addresses,
    # timestamps, ports and source filenames are intentionally excluded.
    FEATURE_COLUMNS = [
        "packet_count",
        "avg_packet_size",
        "std_packet_size",
        "min_packet_size",
        "max_packet_size",
        "total_bytes",
        "unique_destinations",
        "unique_destination_ports",
        "unique_source_ports",
        "protocol_count",
        "flow_duration",
        "packets_per_second",
        "syn_count",
        "syn_ratio",
        "rst_count",
        "rst_ratio",
        "ssh_packet_count",
        "ssh_ratio",
        "avg_interarrival_time",
        "std_interarrival_time",
        "max_packets_per_second",
    ]

    @classmethod
    def ensure_directories(cls) -> None:
        """Create all writable project directories if they do not exist."""
        cls.RAW_DATA.mkdir(parents=True, exist_ok=True)
        cls.PROCESSED_DATA.mkdir(parents=True, exist_ok=True)
        cls.MODELS_DIR.mkdir(parents=True, exist_ok=True)
