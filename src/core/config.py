from pathlib import Path


class Config:

    BASE_DIR = Path(__file__).resolve().parents[2]

    RAW_DATA = BASE_DIR / "data" / "raw"

    PROCESSED_DATA = (
        BASE_DIR / "data" / "processed"
    )

    MODEL_DIR = (
        BASE_DIR / "data" / "models"
    )

    FEATURES_FILE = (
        PROCESSED_DATA / "features.csv"
    )

    MODEL_FILE = (
        MODEL_DIR /
        "isolation_forest.pkl"
    )