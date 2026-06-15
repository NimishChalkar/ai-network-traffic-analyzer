import streamlit as st
import pandas as pd

st.title(
    "AI Network Traffic Analyzer"
)

df = pd.read_csv(
    "data/processed/features.csv"
)

st.metric(
    "Unique Hosts",
    len(df)
)

st.dataframe(df)

if "prediction" in df.columns:

    anomalies = df[
        df["prediction"] == -1
    ]

    st.metric(
        "Anomalies",
        len(anomalies)
    )

    st.dataframe(
        anomalies
    )