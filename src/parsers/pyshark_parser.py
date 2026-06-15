import pyshark
import pandas as pd


class PysharkParser:

    def __init__(
        self,
        pcap_file
    ):

        self.pcap_file = pcap_file

    def parse(self):

        packets = []

        capture = pyshark.FileCapture(
            self.pcap_file,
            keep_packets=False
        )

        for packet in capture:

            try:

                packets.append({

                    "src_ip":
                    packet.ip.src,

                    "dst_ip":
                    packet.ip.dst,

                    "protocol":
                    packet.transport_layer,

                    "length":
                    int(packet.length)

                })

            except Exception:

                continue

        return pd.DataFrame(
            packets
        )