from parsers.pcap_parser import PcapParser
from features.feature_extractor import FeatureExtractor
from core.config import Config
import pandas as pd


class DatasetBuilder:

    def __init__(self):

        self.extractor = FeatureExtractor()

        self.pcap_map = {
            "normal.pcap": "normal",
            "nmap_scan.pcap": "nmap",
            "hydra_attack.pcap": "hydra",
            "dos_attack.pcap": "dos"
        }

    def build(self):

        all_data = []

        for file_name, label in self.pcap_map.items():

            print(f"[+] Processing {file_name} as {label}")

            parser = PcapParser(
                Config.RAW_DATA / file_name
            )

            packets = parser.parse()

            features = self.extractor.extract(packets)

            features["attack_type"] = label

            all_data.append(features)

        final_df = pd.concat(all_data, ignore_index=True)

        output_path = (
            Config.PROCESSED_DATA /
            "dataset.csv"
        )

        final_df.to_csv(output_path, index=False)

        print(f"[+] Dataset saved to {output_path}")

        return final_df


if __name__ == "__main__":

    builder = DatasetBuilder()

    df = builder.build()

    print(df.head())