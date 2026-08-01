from pathlib import Path

import pandas as pd

from src.core.config import Config
from src.features.feature_extractor import FeatureExtractor
from src.parsers.pcap_parser import PcapParser


class DatasetBuilder:
    """Build a labelled, window-based dataset from every raw PCAP."""

    def __init__(self) -> None:
        Config.ensure_directories()
        self.extractor = FeatureExtractor(Config.WINDOW_SECONDS)
        self.pcap_files = sorted(Config.RAW_DATA.glob("*.pcap"))
        print(f"\n[+] Found {len(self.pcap_files)} PCAP files")

    @staticmethod
    def infer_label(filename: str) -> str | None:
        """Infer the controlled-lab class label from the PCAP filename."""
        name = filename.lower()

        if "normal" in name:
            return "normal"
        if "nmap" in name:
            return "nmap"
        if "hydra" in name:
            return "hydra"
        if "dos" in name:
            return "dos"
        return None

    def build(self) -> pd.DataFrame:
        """Parse, window, label and combine all supported PCAP files."""
        if not self.pcap_files:
            raise FileNotFoundError(
                f"No .pcap files were found in {Config.RAW_DATA}"
            )

        datasets: list[pd.DataFrame] = []
        failures: list[str] = []

        print(
            f"\n[+] Building {Config.WINDOW_SECONDS}-second "
            "source-behaviour windows...\n"
        )

        for index, pcap_file in enumerate(self.pcap_files, start=1):
            label = self.infer_label(pcap_file.name)

            if label is None:
                print(
                    f"[{index}/{len(self.pcap_files)}] "
                    f"Skipping unrecognised file: {pcap_file.name}"
                )
                continue

            print(
                f"[{index}/{len(self.pcap_files)}] "
                f"{pcap_file.name} -> {label}"
            )

            try:
                packets = PcapParser(pcap_file).parse()
                if packets.empty:
                    print("    [!] No IPv4 packets found; skipped.")
                    continue

                features = self.extractor.extract(packets)
                if features.empty:
                    print("    [!] No feature windows produced; skipped.")
                    continue

                features["source_file"] = pcap_file.name
                features["attack_type"] = label
                datasets.append(features)

                print(
                    f"    [+] Feature windows generated: "
                    f"{len(features):,}"
                )
            except Exception as exc:
                failures.append(f"{pcap_file.name}: {exc}")
                print(f"    [!] Failed: {exc}")

        if not datasets:
            raise RuntimeError(
                "Dataset build produced no rows. Review the PCAP files "
                "and parser output."
            )

        dataset = pd.concat(datasets, ignore_index=True)
        dataset = dataset.sort_values(
            ["window_start", "source_file", "src_ip"]
        ).reset_index(drop=True)

        dataset.to_csv(Config.DATASET_PATH, index=False)

        print("\n[+] DATASET BUILD COMPLETE")
        print(f"[+] Saved to: {Config.DATASET_PATH}")
        print(f"[+] Dataset shape: {dataset.shape}")
        print("\n[+] Class distribution:")
        print(dataset["attack_type"].value_counts())

        if failures:
            print("\n[!] Files that could not be processed:")
            for failure in failures:
                print(f"    - {failure}")

        return dataset


if __name__ == "__main__":
    built_dataset = DatasetBuilder().build()
    print("\n[+] Dataset preview:")
    print(built_dataset.head())
