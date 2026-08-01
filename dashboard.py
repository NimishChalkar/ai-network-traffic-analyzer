import pandas as pd
import streamlit as st

from src.core.config import Config
from src.detection.predictor import Predictor
from src.visualization.alert_engine import AlertEngine
from src.visualization.timeline import TimelineEngine


st.set_page_config(
    page_title="AI Network SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AI Network Traffic Analyzer")
st.caption(
    "Flow-window classification, MITRE ATT&CK enrichment and "
    "deduplicated SOC alerting"
)


@st.cache_data
def load_dataset() -> pd.DataFrame:
    return pd.read_csv(Config.DATASET_PATH)


@st.cache_resource
def load_predictor() -> Predictor:
    return Predictor()


try:
    dataset = load_dataset()
    predictions = load_predictor().predict(dataset)
except FileNotFoundError as exc:
    st.error(str(exc))
    st.stop()
except Exception as exc:
    st.exception(exc)
    st.stop()


alerts = AlertEngine().generate_alerts(predictions)
timeline = TimelineEngine().build_timeline(alerts)

# Sidebar filters
st.sidebar.header("Filters")
attack_options = sorted(alerts["attack"].unique()) if not alerts.empty else []
selected_attacks = st.sidebar.multiselect(
    "Attack type",
    options=attack_options,
    default=attack_options,
)

severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
available_severities = [
    value for value in severity_order
    if value in set(alerts.get("severity", pd.Series(dtype=str)))
]
selected_severities = st.sidebar.multiselect(
    "Severity",
    options=available_severities,
    default=available_severities,
)

filtered_alerts = alerts.copy()
if selected_attacks:
    filtered_alerts = filtered_alerts[
        filtered_alerts["attack"].isin(selected_attacks)
    ]
if selected_severities:
    filtered_alerts = filtered_alerts[
        filtered_alerts["severity"].isin(selected_severities)
    ]

# KPI row
total_windows = len(predictions)
suspicious_windows = int((predictions["prediction"] != "normal").sum())
deduplicated_alerts = len(alerts)
critical_alerts = int((alerts["severity"] == "CRITICAL").sum()) if not alerts.empty else 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("Traffic Windows", f"{total_windows:,}")
col2.metric("Suspicious Windows", f"{suspicious_windows:,}")
col3.metric("Deduplicated Alerts", f"{deduplicated_alerts:,}")
col4.metric("Critical Alerts", f"{critical_alerts:,}")

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Attack Distribution")
    attack_counts = (
        predictions["prediction"]
        .value_counts()
        .rename_axis("attack")
        .to_frame("count")
    )
    st.bar_chart(attack_counts)

with right:
    st.subheader("Alert Severity Distribution")
    if alerts.empty:
        st.info("No suspicious alerts were generated.")
    else:
        severity_counts = (
            alerts["severity"]
            .value_counts()
            .reindex(severity_order)
            .dropna()
            .rename_axis("severity")
            .to_frame("count")
        )
        st.bar_chart(severity_counts)

st.divider()

st.subheader("🚨 Deduplicated Alert Feed")
if filtered_alerts.empty:
    st.info("No alerts match the selected filters.")
else:
    st.dataframe(
        filtered_alerts[
            [
                "alert_id",
                "timestamp",
                "last_seen",
                "src_ip",
                "dst_ip",
                "attack",
                "severity",
                "risk_score",
                "confidence",
                "occurrences",
                "packet_count",
                "mitre",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

st.divider()

st.subheader("📅 Attack Timeline")
filtered_timeline = TimelineEngine().build_timeline(filtered_alerts)

if filtered_timeline.empty:
    st.info("No timeline events match the selected filters.")
else:
    for row in filtered_timeline.itertuples(index=False):
        icon = {
            "CRITICAL": "🚨",
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }.get(row.severity, "⚪")

        with st.expander(
            f"{icon} {row.timestamp} | "
            f"{str(row.attack).upper()} | "
            f"{row.src_ip} → {row.dst_ip}"
        ):
            st.write(f"**Alert ID:** {row.alert_id}")
            st.write(f"**Stage:** {row.incident_stage}")
            st.write(f"**Severity:** {row.severity}")
            st.write(f"**Risk score:** {row.risk_score}")
            st.write(f"**Confidence:** {row.confidence}%")
            st.write(f"**Occurrences:** {row.occurrences}")
            st.write(f"**MITRE ATT&CK:** {row.mitre}")

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Model Feature Importance")
    if Config.FEATURE_IMPORTANCE_PATH.exists():
        importance = pd.read_csv(Config.FEATURE_IMPORTANCE_PATH)
        st.bar_chart(
            importance.set_index("feature")["importance"]
        )
    else:
        st.warning("Run train.py to generate feature importance.")

with right:
    st.subheader("Confusion Matrix")
    if Config.CONFUSION_MATRIX_PATH.exists():
        st.image(
            str(Config.CONFUSION_MATRIX_PATH),
            use_container_width=True,
        )
    else:
        st.warning("Run train.py to generate the confusion matrix.")

st.divider()

st.subheader("Recent Network Behaviour Windows")
display_columns = [
    "window_start",
    "window_end",
    "source_file",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_count",
    "total_bytes",
    "prediction",
    "confidence",
]
st.dataframe(
    predictions.reindex(columns=display_columns).tail(100),
    use_container_width=True,
    hide_index=True,
)
