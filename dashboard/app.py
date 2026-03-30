import sys
import os

# 🔥 Fix import path FIRST
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import json
from datetime import datetime
import pandas as pd

from engine.correlator import correlate_alerts
from engine.analyzer import analyze_logs

# =========================
# 🧠 HELPER FUNCTIONS
# =========================

def severity_badge(severity):
    colors = {
        "CRITICAL": "red",
        "HIGH": "orange",
        "MEDIUM": "blue",
        "LOW": "green"
    }
    color = colors.get(severity, "gray")
    return f"<span style='color:white; background-color:{color}; padding:4px 10px; border-radius:8px;'>{severity}</span>"


def time_ago(ts):
    try:
        event_time = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        diff = now - event_time
        seconds = diff.total_seconds()

        if seconds < 60:
            return "Just now"
        elif seconds < 3600:
            return f"{int(seconds//60)} min ago"
        elif seconds < 86400:
            return f"{int(seconds//3600)} hrs ago"
        else:
            return f"{int(seconds//86400)} days ago"
    except:
        return ts


def parse_time(alert):
    try:
        return datetime.strptime(alert.get("timestamp"), "%Y-%m-%d %H:%M:%S")
    except:
        return datetime.min


def guess_column(columns, keywords):
    for col in columns:
        for k in keywords:
            if k in col.lower():
                return col
    return None


def anomaly_label(score):
    if score < -0.2:
        return "🔴 Highly Anomalous"
    elif score < -0.1:
        return "🟠 Suspicious"
    else:
        return "🟢 Normal"


# =========================
# 🚀 UI START
# =========================

st.set_page_config(page_title="Verdict Dashboard", layout="wide")
st.title("🛡️ Verdict - Explainable SOC Dashboard")

st.info("👈 Upload a CSV file from sidebar to start analysis")

# =========================
# SESSION STORAGE
# =========================

if "user_alerts" not in st.session_state:
    st.session_state["user_alerts"] = []

# =========================
# SIDEBAR
# =========================

st.sidebar.header("📂 Upload Logs")

uploaded_file = st.sidebar.file_uploader("Upload your CSV log file", type=["csv"])
# 🔒 File size protection (5MB)
MAX_FILE_SIZE_MB = 5

if uploaded_file is not None:
    file_size_mb = uploaded_file.size / (1024 * 1024)
    if file_size_mb > MAX_FILE_SIZE_MB:
        st.error(f"File too large ({round(file_size_mb,2)} MB). Max allowed is {MAX_FILE_SIZE_MB} MB.")
        st.stop()


# 🔥 ML SLIDER
st.sidebar.subheader("🧠 ML Sensitivity")

threshold = st.sidebar.slider(
    "Anomaly Threshold",
    min_value=-0.3,
    max_value=0.0,
    value=-0.1,
    step=0.01,
    help="Lower = stricter detection, Higher = more sensitive"
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# =========================
# FILE PROCESSING
# =========================

if uploaded_file:

    try:
        df = pd.read_csv(uploaded_file)
        MAX_ROWS = 5000
        if len(df) > MAX_ROWS:
            st.warning(f"Large dataset detected. Showing first {MAX_ROWS} rows only.")
            df = df.head(MAX_ROWS)
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()

    columns = df.columns.tolist()

    st.sidebar.subheader("🧠 Column Mapping")

    process_guess = guess_column(columns, ["process", "image", "exe"])
    cmd_guess = guess_column(columns, ["command", "cmd"])
    ip_guess = guess_column(columns, ["ip", "dest"])
    time_guess = guess_column(columns, ["time", "timestamp"])

    process_col = st.sidebar.selectbox(
        "Process Column",
        columns,
        index=columns.index(process_guess) if process_guess in columns else 0
    )

    cmd_col = st.sidebar.selectbox(
        "Command Column",
        columns,
        index=columns.index(cmd_guess) if cmd_guess in columns else 0
    )

    ip_col = st.sidebar.selectbox(
        "IP Column",
        columns,
        index=columns.index(ip_guess) if ip_guess in columns else 0
    )

    time_col = st.sidebar.selectbox(
        "Timestamp Column",
        columns,
        index=columns.index(time_guess) if time_guess in columns else 0
    )

    # Validate columns
    required_cols = [process_col, cmd_col, ip_col, time_col]

    for col in required_cols:
        if col not in df.columns:
            st.error(f"Missing column: {col}")
            st.stop()

    # Normalize
    df_normalized = pd.DataFrame({
        "process": df[process_col],
        "command_line": df[cmd_col],
        "ip": df[ip_col],
        "timestamp": pd.to_datetime(df[time_col], errors="coerce").astype(str)
    })

    temp_path = os.path.join(BASE_DIR, "data/user_uploaded.csv")
    df_normalized.to_csv(temp_path, index=False)

    # 🔥 Pass threshold here
    try:
        alerts, rows = analyze_logs(temp_path, anomaly_threshold=threshold)
    except Exception as e:
        st.error(f"Detection error: {e}")
        st.stop()

    for alert, row in zip(alerts, rows):
        alert["timestamp"] = row.get("timestamp")

    st.session_state["user_alerts"] = alerts

    st.sidebar.success(f"✅ {len(alerts)} alerts generated")

# =========================
# NAVIGATION
# =========================

page = st.sidebar.radio("📂 Navigation", ["Alerts", "Attack Stories"])

# =========================
# LOAD ALERTS
# =========================

if uploaded_file and st.session_state["user_alerts"]:
    alerts = st.session_state["user_alerts"]
else:
    try:
        with open(os.path.join(BASE_DIR, "output/alerts.json"), "r") as f:
            alerts = json.load(f)
    except:
        alerts = []

# =========================
# ALERTS PAGE
# =========================

if page == "Alerts":

    st.sidebar.header("🔍 Filters")

    sort_option = st.sidebar.selectbox("Sort", ["Latest First", "Oldest First"])

    severity_filter = st.sidebar.multiselect(
        "Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=[]
    )

    status_filter = st.sidebar.multiselect(
        "Status", ["OPEN", "INVESTIGATING", "CLOSED"], default=[]
    )

    alerts = sorted(alerts, key=parse_time, reverse=(sort_option == "Latest First"))

    filtered = []
    for alert in alerts:

        if severity_filter and alert.get("severity", "").upper() not in severity_filter:
            continue

        status = alert.get("status", "OPEN").upper()
        if status_filter and status not in status_filter:
            continue

        filtered.append(alert)

    st.subheader(f"Showing {len(filtered)} Alerts")

    if not filtered:
        st.warning("No alerts found")

    for alert in filtered:

        st.markdown(
            f"### 🚨 {severity_badge(alert.get('severity'))} - {alert.get('process')}",
            unsafe_allow_html=True
        )

        if alert.get("severity") == "CRITICAL":
            st.error("🚨 CRITICAL ALERT – Immediate action required!")

        st.write(f"⏱️ {time_ago(alert.get('timestamp'))}")

        # 🔥 ANOMALY DISPLAY
        if "anomaly_score" in alert:
            score = alert.get("anomaly_score", 0)
            st.write(f"🧠 Anomaly Score: {round(score, 3)}")
            st.write(f"📊 ML Verdict: {anomaly_label(score)}")

        col1, col2 = st.columns(2)

        with col1:
            st.write("**Reasons:**")
            for r in alert.get("reasons", []):
                st.write(f"- {r}")

            st.write("**Explanation:**")
            for exp in alert.get("explanations", []):
                st.write(f"- {exp}")

        with col2:
            st.write("**MITRE Techniques:**")
            for m in alert.get("mitre", []):
                st.write(f"- {m}")

            st.write(f"**Confidence:** {alert.get('confidence')}")

        st.markdown("---")

    # Download
    if uploaded_file and filtered:
        df_export = pd.DataFrame(filtered)
        csv = df_export.to_csv(index=False)

        st.download_button(
            "💾 Download Alerts",
            csv,
            file_name="verdict_alerts.csv",
            mime="text/csv"
        )

# =========================
# ATTACK STORIES
# =========================

elif page == "Attack Stories":

    st.header("🔥 Attack Stories")

    stories = correlate_alerts(alerts)

    if not stories:
        st.info("No correlated attacks found")
        st.stop()

    for story in stories:

        st.markdown(f"## 🚨 {story['process']}")
        st.write(f"Events: {story['event_count']}")
        st.write(f"Threat Score: {story['score']}")

        st.write("### 🕒 Timeline")

        for event in story["timeline"]:
            st.info(
                f"{time_ago(event.get('timestamp'))} → {event.get('process')} | {', '.join(event.get('reasons', []))}"
            )

        st.write("### MITRE Chain")
        for m in story["mitre_chain"]:
            st.write(f"- {m}")

        st.markdown("---")
