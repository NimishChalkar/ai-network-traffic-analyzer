import pandas as pd


class FeatureExtractor:

    def extract(
        self,
        dataframe
    ):

        grouped = (

            dataframe
            .groupby("src_ip")
            .agg({

                "length":
                ["count", "mean", "sum"],

                "dst_ip":
                "nunique",

                "protocol":
                "nunique"
            })

        )

        grouped.columns = [

            "packet_count",
            "avg_packet_size",
            "total_bytes",
            "unique_destinations",
            "protocol_count"
        ]

        return (
            grouped
            .reset_index()
        )