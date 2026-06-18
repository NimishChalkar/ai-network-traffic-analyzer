from parsers.pcap_parser import PcapParser
from features.feature_extractor import FeatureExtractor
from detection.anomaly_detector import AnomalyDetector
from core.config import Config


def main():

    parser = PcapParser(
        Config.RAW_DATA /
        "normal.pcap"
    )

    packets = parser.parse()

    extractor = (
        FeatureExtractor()
    )

    features = (
        extractor.extract(
            packets
        )
    )

    features.to_csv(

        Config.FEATURES_FILE,

        index=False

    )

    detector = (
        AnomalyDetector()
    )

    detector.train(
        features
    )

    predictions = (
        detector.predict(
            features
        )
    )

    features[
        "prediction"
    ] = predictions

    print(features)


if __name__ == "__main__":

    main()