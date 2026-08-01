from pathlib import Path
from typing import Optional

import pandas as pd
from scapy.all import ICMP, IP, TCP, UDP, PcapReader


class PcapParser:
    """
    Stream a PCAP with Scapy and convert IPv4 packets into tabular records.

    PcapReader is used instead of rdpcap so large DoS captures are not loaded
    completely into memory.
    """

    OUTPUT_COLUMNS = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packet_size",
        "tcp_flags",
        "is_syn",
        "is_ack",
        "is_rst",
        "is_fin",
    ]

    def __init__(
        self,
        pcap_file: str | Path,
        max_packets: Optional[int] = None,
        sample_every: int = 1,
    ) -> None:
        self.pcap_file = Path(pcap_file)
        self.max_packets = max_packets
        self.sample_every = max(1, sample_every)

    def parse(self) -> pd.DataFrame:
        """
        Parse the capture and return one row per IPv4 packet.

        Returns:
            DataFrame containing timestamps, addresses, ports, protocol,
            packet size and selected TCP flag indicators.
        """
        if not self.pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")

        print(f"[+] Parsing PCAP: {self.pcap_file.name}")

        records: list[dict] = []
        inspected_packets = 0

        with PcapReader(str(self.pcap_file)) as capture:
            for packet_index, packet in enumerate(capture):
                if self.max_packets is not None and inspected_packets >= self.max_packets:
                    break

                if packet_index % self.sample_every != 0:
                    continue

                inspected_packets += 1

                if IP not in packet:
                    continue

                src_port = 0
                dst_port = 0
                protocol = "OTHER"
                tcp_flags = 0

                if TCP in packet:
                    protocol = "TCP"
                    src_port = int(packet[TCP].sport)
                    dst_port = int(packet[TCP].dport)
                    tcp_flags = int(packet[TCP].flags)
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = int(packet[UDP].sport)
                    dst_port = int(packet[UDP].dport)
                elif ICMP in packet:
                    protocol = "ICMP"

                records.append(
                    {
                        "timestamp": float(packet.time),
                        "src_ip": str(packet[IP].src),
                        "dst_ip": str(packet[IP].dst),
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "packet_size": int(len(packet)),
                        "tcp_flags": tcp_flags,
                        "is_syn": int(bool(tcp_flags & 0x02)),
                        "is_ack": int(bool(tcp_flags & 0x10)),
                        "is_rst": int(bool(tcp_flags & 0x04)),
                        "is_fin": int(bool(tcp_flags & 0x01)),
                    }
                )

        dataframe = pd.DataFrame(records, columns=self.OUTPUT_COLUMNS)
        print(f"    [+] IPv4 packet rows: {len(dataframe):,}")
        return dataframe
