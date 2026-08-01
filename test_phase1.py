from src.parsers.pcap_parser import PcapParser
from src.features.feature_extractor import FeatureExtractor

pcap_file = "data/raw/normal_01.pcap"

parser = PcapParser(pcap_file)
packets = parser.parse()

extractor = FeatureExtractor()
features = extractor.extract(packets)

print("\n=== FEATURES ===")
print(features)