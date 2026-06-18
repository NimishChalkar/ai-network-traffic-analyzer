from parsers.pcap_parser import PcapParser
from features.feature_extractor import FeatureExtractor
from detection.anomaly_detector import AnomalyDetector
from core.config import Config
from detection.attack_classifier import AttackClassifier
import pandas as pd


def main():

    df = pd.read_csv("data/processed/dataset.csv")

    print(f"Loaded dataset: {df.shape}")

    classifier = AttackClassifier()

    classifier.train(df)

    classifier.save("data/models/attack_classifier.pkl")


if __name__ == "__main__":

    main()