import pandas as pd

from src.core.config import Config
from src.detection.attack_classifier import AttackClassifier


def main() -> None:
    """Load the generated dataset, train the model and save artefacts."""
    if not Config.DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {Config.DATASET_PATH}. "
            "Run `python3 -m src.data.data_builder` first."
        )

    dataset = pd.read_csv(Config.DATASET_PATH)
    print(f"[+] Loaded dataset: {dataset.shape}")

    classifier = AttackClassifier()
    classifier.train(dataset)
    classifier.save()


if __name__ == "__main__":
    main()
