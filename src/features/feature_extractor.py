import pandas as pd


class FeatureExtractor:

    def extract(self, dataframe):

        features = (

            dataframe
            .groupby("src_ip")
            .agg(
                {
                    "length": ["count", "mean", "sum"],
                    "dst_ip": "nunique",
                    "dst_port": "nunique",
                    "protocol": "nunique"
                }
            )

        )

        features.columns = [

            "packet_count",
            "avg_packet_size",
            "total_bytes",
            "unique_destinations",
            "unique_ports",
            "protocol_count"
        ]

        return features.reset_index()