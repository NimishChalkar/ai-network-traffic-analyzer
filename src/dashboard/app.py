import streamlit as st
import pandas as pd
import plotly.express as px

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="AI SOC Network Analyzer",
    layout="wide"
)

st.title("🚨 AI Network Traffic Analyzer (SOC Dashboard)")

# =========================
# LOAD DATA
# =========================
df = pd.read_csv("data/processed/dataset.csv")
fi = pd.read_csv("data/processed/feature_importance.csv")

# =========================
# KPIs
# =========================
st.subheader("📊 SOC Overview Metrics")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Records", len(df))
col2.metric("Unique Sources", df["src_ip"].nunique())
col3.metric("Attack Types", df["attack_type"].nunique())
col4.metric("Total Packets", int(df["packet_count"].sum()))

st.divider()

# =========================
# FEATURE IMPORTANCE
# =========================
st.subheader("🔍 Feature Importance (Model Explainability)")

fig_fi = px.bar(
    fi,
    x="importance",
    y="feature",
    orientation="h",
    title="Feature Importance Ranking"
)

st.plotly_chart(fig_fi, use_container_width=True)

st.divider()

# =========================
# ATTACK DISTRIBUTION
# =========================
st.subheader("📡 Attack Type Distribution")

fig_attack = px.histogram(
    df,
    x="attack_type",
    color="attack_type",
    title="Traffic Distribution by Attack Type"
)

st.plotly_chart(fig_attack, use_container_width=True)

st.divider()

# =========================
# TOP TALKERS
# =========================
st.subheader("🔥 Top Talkers (Source IPs)")

top_talkers = (
    df.groupby("src_ip")["packet_count"]
    .sum()
    .sort_values(ascending=False)
    .head(10)
    .reset_index()
)

fig_talkers = px.bar(
    top_talkers,
    x="src_ip",
    y="packet_count",
    title="Top Source IPs by Traffic Volume"
)

st.plotly_chart(fig_talkers, use_container_width=True)

st.divider()

# =========================
# SIEM-STYLE ALERT ENGINE
# =========================
st.subheader("🚨 Live SOC Alert Feed (Simulated SIEM)")

alerts = df[df["attack_type"] != "normal"].copy()

# Severity mapping
def get_severity(row):

    if row["attack_type"] == "dos":
        return "HIGH"

    elif row["attack_type"] == "hydra":
        return "CRITICAL"

    elif row["attack_type"] == "nmap":
        return "MEDIUM"

    return "LOW"


alerts["severity"] = alerts.apply(get_severity, axis=1)

# KPIs for alerts
colA, colB, colC = st.columns(3)

colA.metric("Total Alerts", len(alerts))
colB.metric("Critical Alerts", len(alerts[alerts["severity"] == "CRITICAL"]))
colC.metric("High Severity", len(alerts[alerts["severity"] == "HIGH"]))

st.divider()

# Alert table
st.dataframe(
    alerts[[
        "src_ip",
        "attack_type",
        "severity",
        "packet_count",
        "total_bytes",
        "unique_ports"
    ]],
    use_container_width=True
)

st.divider()

# =========================
# RAW DATA VIEW
# =========================
st.subheader("📁 Dataset Explorer")

st.dataframe(df, use_container_width=True)