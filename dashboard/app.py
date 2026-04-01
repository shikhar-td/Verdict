import sys
import os

# 🔥 Fix import path FIRST
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import json
from datetime import datetime
import pandas as pd
import plotly.express as px

from engine.correlator import correlate_alerts
from engine.analyzer import analyze_logs

# =========================
# 🧠 HELPER FUNCTIONS
# =========================

def severity_badge(severity):
    colors = {
        "CRITICAL": "#FF3366", # Vibrant Red/Pink
        "HIGH": "#FF9933",     # Orange
        "MEDIUM": "#FFCC00",   # Yellow
        "LOW": "#33CCFF"       # Cyan
    }
    color = colors.get(severity.upper(), "gray")
    return f"<span style='color:black; font-weight:bold; background-color:{color}; padding:4px 12px; border-radius:4px;'>{severity}</span>"

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
        return datetime.strptime(alert.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
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
# 🚀 UI & THEME SETUP
# =========================

st.set_page_config(page_title="Verdict | SOC Dashboard", page_icon="🛡️", layout="wide")

# Professional Dark Theme CSS
st.markdown("""
    <style>
    .stApp { background-color: #0E1117; }
    .metric-card { background-color: #1E2127; padding: 15px; border-radius: 8px; border-left: 4px solid #00FFAA; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
    hr { margin-top: 1rem; margin-bottom: 1rem; border: 0; border-top: 1px solid rgba(255, 255, 255, 0.1); }
    </style>
""", unsafe_allow_html=True)

# =========================
# SESSION STORAGE
# =========================
if "user_alerts" not in st.session_state:
    st.session_state["user_alerts"] = []

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# =========================
# SIDEBAR INGESTION & CONFIG
# =========================

with st.sidebar:
    st.title("🛡️ Verdict Ingestion")
    st.markdown("---")
    
    st.header("1. Upload Logs")
    uploaded_file = st.file_uploader("Upload CSV Log File", type=["csv"])
    
    # 🔒 File size protection (5MB)
    MAX_FILE_SIZE_MB = 5
    if uploaded_file is not None:
        file_size_mb = uploaded_file.size / (1024 * 1024)
        if file_size_mb > MAX_FILE_SIZE_MB:
            st.error(f"File too large ({round(file_size_mb,2)} MB). Max allowed is {MAX_FILE_SIZE_MB} MB.")
            st.stop()

    st.markdown("---")
    st.header("2. Engine Sensitivity")
    threshold = st.slider(
        "ML Anomaly Threshold",
        min_value=-0.3, max_value=0.0, value=-0.1, step=0.01,
        help="Lower = stricter detection, Higher = more sensitive"
    )

# =========================
# FILE PROCESSING PIPELINE
# =========================

if uploaded_file:
    try:
        df = pd.read_csv(uploaded_file)
        MAX_ROWS = 5000
        if len(df) > MAX_ROWS:
            st.toast(f"Large dataset detected. Processing first {MAX_ROWS} rows only.", icon="⚠️")
            df = df.head(MAX_ROWS)
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()

    columns = df.columns.tolist()

    with st.sidebar.expander("⚙️ Advanced Column Mapping", expanded=True):
        process_guess = guess_column(columns, ["process", "image", "exe"])
        cmd_guess = guess_column(columns, ["command", "cmd"])
        ip_guess = guess_column(columns, ["ip", "dest"])
        time_guess = guess_column(columns, ["time", "timestamp"])

        process_col = st.selectbox("Process Column", columns, index=columns.index(process_guess) if process_guess in columns else 0)
        cmd_col = st.selectbox("Command Column", columns, index=columns.index(cmd_guess) if cmd_guess in columns else 0)
        ip_col = st.selectbox("IP Column", columns, index=columns.index(ip_guess) if ip_guess in columns else 0)
        time_col = st.selectbox("Timestamp Column", columns, index=columns.index(time_guess) if time_guess in columns else 0)

    # Validate columns
    required_cols = [process_col, cmd_col, ip_col, time_col]
    for col in required_cols:
        if col not in df.columns:
            st.sidebar.error(f"Missing column: {col}")
            st.stop()

    # Normalize & Save
    df_normalized = pd.DataFrame({
        "process": df[process_col],
        "command_line": df[cmd_col],
        "ip": df[ip_col],
        "timestamp": pd.to_datetime(df[time_col], errors="coerce").astype(str)
    })

    temp_path = os.path.join(BASE_DIR, "data/user_uploaded.csv")
    # Ensure data dir exists
    os.makedirs(os.path.dirname(temp_path), exist_ok=True)
    df_normalized.to_csv(temp_path, index=False)

    # Run Analysis
    with st.spinner("Analyzing logs via Hybrid Engine..."):
        try:
            alerts, rows = analyze_logs(temp_path, anomaly_threshold=threshold)
            for alert, row in zip(alerts, rows):
                alert["timestamp"] = row.get("timestamp")
            st.session_state["user_alerts"] = alerts
            st.sidebar.success(f"✅ {len(alerts)} alerts generated")
        except Exception as e:
            st.error(f"Detection error: {e}")
            st.stop()

# =========================
# DATA LOADING (Fallback)
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
# MAIN DASHBOARD VIEW
# =========================
if not alerts:
    st.info("👈 Awaiting data. Please upload a CSV file from the sidebar to start analysis, or ensure 'output/alerts.json' exists.")
    st.stop()

# --- TOP KPI ROW ---
crit_count = sum(1 for a in alerts if a.get("severity", "").upper() == "CRITICAL")
high_count = sum(1 for a in alerts if a.get("severity", "").upper() == "HIGH")
avg_anomaly = sum(a.get("anomaly_score", 0) for a in alerts) / len(alerts) if alerts else 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Active Alerts", len(alerts))
col2.metric("Critical Threats", crit_count, "Immediate Action Req." if crit_count > 0 else None, delta_color="inverse")
col3.metric("High Severity", high_count)
col4.metric("Avg ML Anomaly Score", round(avg_anomaly, 3))

st.markdown("---")

# --- TABBED INTERFACE ---
tab1, tab2, tab3 = st.tabs(["📊 Analytics Overview", "🚨 Alert Triage Queue", "🔗 Attack Stories (Correlation)"])

# ----------------- TAB 1: ANALYTICS -----------------
with tab1:
    st.subheader("Threat Landscape Overview")
    df_alerts = pd.DataFrame(alerts)
    
    if not df_alerts.empty:
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            if 'severity' in df_alerts.columns:
                fig_sev = px.pie(df_alerts, names='severity', title='Alerts by Severity', hole=0.4, 
                                 color_discrete_map={"CRITICAL":"#FF3366", "HIGH":"#FF9933", "MEDIUM":"#FFCC00", "LOW":"#33CCFF"})
                fig_sev.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig_sev, use_container_width=True)
                
        with chart_col2:
            if 'mitre' in df_alerts.columns:
                # Flatten MITRE lists for counting
                all_mitre = [m for sublist in df_alerts['mitre'].dropna() for m in sublist]
                if all_mitre:
                    mitre_counts = pd.Series(all_mitre).value_counts().reset_index()
                    mitre_counts.columns = ['Tactic', 'Count']
                    fig_mitre = px.bar(mitre_counts, x='Count', y='Tactic', orientation='h', title='MITRE ATT&CK Tactics', color='Count', color_continuous_scale='Reds')
                    fig_mitre.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', yaxis={'categoryorder':'total ascending'})
                    st.plotly_chart(fig_mitre, use_container_width=True)

# ----------------- TAB 2: ALERT TRIAGE -----------------
with tab2:
    st.subheader("Active Investigation Queue")
    
    # Inline Filters
    filt_col1, filt_col2, filt_col3 = st.columns(3)
    sort_option = filt_col1.selectbox("Sort Timeline", ["Latest First", "Oldest First"])
    severity_filter = filt_col2.multiselect("Filter Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=[])
    status_filter = filt_col3.multiselect("Filter Status", ["OPEN", "INVESTIGATING", "CLOSED"], default=[])

    # Apply Filters
    filtered_alerts = sorted(alerts, key=parse_time, reverse=(sort_option == "Latest First"))
    final_alerts = []
    for alert in filtered_alerts:
        if severity_filter and alert.get("severity", "").upper() not in severity_filter:
            continue
        if status_filter and alert.get("status", "OPEN").upper() not in status_filter:
            continue
        final_alerts.append(alert)

    # Display Alerts natively as expanders
    for alert in final_alerts:
        severity = alert.get('severity', 'UNKNOWN')
        timestamp = alert.get('timestamp', 'Unknown Time')
        process = alert.get('process', 'Unknown Process')
        
        # Header for the expander
        header_title = f"{severity} | {process} | {time_ago(timestamp)}"
        if severity == "CRITICAL":
            header_title = "🔥 " + header_title
            
        with st.expander(header_title):
            st.markdown(f"**Severity:** {severity_badge(severity)} &nbsp;&nbsp;|&nbsp;&nbsp; **Timestamp:** `{timestamp}`", unsafe_allow_html=True)
            
            det_col1, det_col2 = st.columns([2, 1])
            with det_col1:
                st.markdown("#### 🔍 Explainability Context")
                st.write("**Detection Reasons:**")
                for r in alert.get("reasons", []):
                    st.markdown(f"- {r}")
                
                st.write("**Engine Explanation:**")
                for exp in alert.get("explanations", []):
                    st.markdown(f"- *{exp}*")
                    
            with det_col2:
                st.markdown("#### ⚙️ Engine Metrics")
                if "anomaly_score" in alert:
                    score = alert.get("anomaly_score", 0)
                    st.metric("ML Anomaly Score", round(score, 3), anomaly_label(score), delta_color="off")
                
                st.write("**Confidence:**", alert.get("confidence", "N/A"))
                
                st.write("**MITRE Chain:**")
                for m in alert.get("mitre", []):
                    st.code(m)

    # Download Button
    if uploaded_file and final_alerts:
        st.markdown("---")
        df_export = pd.DataFrame(final_alerts)
        st.download_button("💾 Download Triaged Alerts (CSV)", df_export.to_csv(index=False), file_name="verdict_alerts.csv", mime="text/csv", type="primary")

# ----------------- TAB 3: ATTACK STORIES -----------------
with tab3:
    st.subheader("Correlated Attack Timelines")
    st.markdown("The correlation engine groups isolated events into broader attack narratives.")
    
    stories = correlate_alerts(alerts)

    if not stories:
        st.success("✅ No correlated attack chains found in the current dataset.")
    else:
        for story in stories:
            with st.container():
                st.markdown(f"### 🔗 Target Process: `{story['process']}`")
                sc1, sc2 = st.columns(2)
                sc1.metric("Events in Chain", story['event_count'])
                sc2.metric("Cumulative Threat Score", story['score'])
                
                st.markdown("#### 🕒 Execution Timeline")
                for event in story["timeline"]:
                    st.info(f"**{time_ago(event.get('timestamp'))}** → {event.get('process')} \n\n *Matched:* {', '.join(event.get('reasons', []))}")
                
                st.markdown("#### 🗺️ MITRE Progression")
                st.markdown(" ➔ ".join([f"`{m}`" for m in story["mitre_chain"]]))
                st.markdown("---")
