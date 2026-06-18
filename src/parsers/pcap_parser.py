from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd


class PcapParser:

    def __init__(self, pcap_file):
        self.pcap_file = str(pcap_file)

    def parse(self):

        records = []

        packets = rdpcap(self.pcap_file)

        for packet in packets:

            try:

                if not packet.haslayer("IP"):
                    continue

                protocol = "OTHER"

                if packet.haslayer("TCP"):
                    protocol = "TCP"

                elif packet.haslayer("UDP"):
                    protocol = "UDP"

                elif packet.haslayer("ICMP"):
                    protocol = "ICMP"

                src_port = 0
                dst_port = 0

                if packet.haslayer("TCP"):
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport

                elif packet.haslayer("UDP"):
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport

                records.append(
                                {
                                    "src_ip": packet[IP].src,
                                    "dst_ip": packet[IP].dst,
                                    "src_port": src_port,
                                    "dst_port": dst_port,
                                    "protocol": protocol,
                                    "length": len(packet)
                                }
                            )

            except Exception:
                continue

        return pd.DataFrame(records)