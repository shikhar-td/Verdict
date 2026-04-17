import json
import os
import sys
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database import (
    get_alert_metrics,
    get_alerts,
    init_database,
    upsert_alerts,
    upsert_events,
)
from engine.analyzer import analyze_logs
from engine.correlator import correlate_alerts
from engine.entity_risk import build_entity_risk
from ingestion.normalize import build_default_mapping, normalize_dataframe
from models import AlertRecord


OPTIONAL_COLUMN_LABEL = "-- None --"


def severity_badge(severity):
    colors = {
        "CRITICAL": "#FF3366",
        "HIGH": "#FF9933",
        "MEDIUM": "#FFCC00",
        "LOW": "#33CCFF",
    }
    color = colors.get(severity.upper(), "gray")
    return (
        f"<span style='color:black; font-weight:bold; background-color:{color}; "
        f"padding:4px 12px; border-radius:4px;'>{severity}</span>"
    )


def time_ago(ts):
    try:
        event_time = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        diff = now - event_time
        seconds = diff.total_seconds()

        if seconds < 60:
            return "Just now"
        if seconds < 3600:
            return f"{int(seconds // 60)} min ago"
        if seconds < 86400:
            return f"{int(seconds // 3600)} hrs ago"
        return f"{int(seconds // 86400)} days ago"
    except Exception:
        return ts


def parse_time(alert):
    try:
        return datetime.strptime(alert.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.min


def select_column(label, columns, guessed_column, optional=False):
    options = columns if not optional else [OPTIONAL_COLUMN_LABEL, *columns]
    default_option = guessed_column if guessed_column in columns else OPTIONAL_COLUMN_LABEL
    index = options.index(default_option) if default_option in options else 0
    selected = st.selectbox(label, options, index=index)
    return None if optional and selected == OPTIONAL_COLUMN_LABEL else selected


def anomaly_label(score):
    if score < -0.2:
        return "Highly Anomalous"
    if score < -0.1:
        return "Suspicious"
    return "Normal"


st.set_page_config(page_title="Verdict | SOC Dashboard", page_icon="shield", layout="wide")

st.markdown(
    """
    <style>
    .stApp { background-color: #0E1117; }
    .metric-card { background-color: #1E2127; padding: 15px; border-radius: 8px; border-left: 4px solid #00FFAA; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
    hr { margin-top: 1rem; margin-bottom: 1rem; border: 0; border-top: 1px solid rgba(255, 255, 255, 0.1); }
    </style>
    """,
    unsafe_allow_html=True,
)

if "user_alerts" not in st.session_state:
    st.session_state["user_alerts"] = []

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
init_database()

with st.sidebar:
    st.title("Verdict Ingestion")
    st.markdown("---")

    st.header("1. Upload Logs")
    uploaded_file = st.file_uploader("Upload CSV Log File", type=["csv"])

    max_file_size_mb = 5
    if uploaded_file is not None:
        file_size_mb = uploaded_file.size / (1024 * 1024)
        if file_size_mb > max_file_size_mb:
            st.error(
                f"File too large ({round(file_size_mb, 2)} MB). Max allowed is {max_file_size_mb} MB."
            )
            st.stop()

    st.markdown("---")
    st.header("2. Engine Sensitivity")
    threshold = st.slider(
        "ML Anomaly Threshold",
        min_value=-0.3,
        max_value=0.0,
        value=-0.1,
        step=0.01,
        help="Lower = stricter detection, Higher = more sensitive",
    )

if uploaded_file:
    try:
        df = pd.read_csv(uploaded_file)
        max_rows = 5000
        if len(df) > max_rows:
            st.toast(
                f"Large dataset detected. Processing first {max_rows} rows only.",
                icon="warning",
            )
            df = df.head(max_rows)
    except Exception as error:
        st.error(f"Error reading file: {error}")
        st.stop()

    columns = df.columns.tolist()
    default_mapping = build_default_mapping(columns)

    with st.sidebar.expander("Advanced Column Mapping", expanded=True):
        process_col = select_column(
            "Process Column",
            columns,
            default_mapping.get("process"),
        )
        cmd_col = select_column(
            "Command Column",
            columns,
            default_mapping.get("command_line"),
        )
        ip_col = select_column(
            "IP Column",
            columns,
            default_mapping.get("ip"),
        )
        time_col = select_column(
            "Timestamp Column",
            columns,
            default_mapping.get("timestamp"),
        )
        parent_process_col = select_column(
            "Parent Process Column",
            columns,
            default_mapping.get("parent_process"),
            optional=True,
        )
        destination_port_col = select_column(
            "Destination Port Column",
            columns,
            default_mapping.get("destination_port"),
            optional=True,
        )
        user_agent_col = select_column(
            "User Agent Column",
            columns,
            default_mapping.get("user_agent"),
            optional=True,
        )
        host_col = select_column(
            "Host Column",
            columns,
            default_mapping.get("host"),
            optional=True,
        )
        user_col = select_column(
            "User Column",
            columns,
            default_mapping.get("user"),
            optional=True,
        )

    required_cols = [process_col, cmd_col, ip_col, time_col]
    for col in required_cols:
        if col not in df.columns:
            st.sidebar.error(f"Missing column: {col}")
            st.stop()

    mapping = {
        "process": process_col,
        "command_line": cmd_col,
        "ip": ip_col,
        "timestamp": time_col,
        "parent_process": parent_process_col,
        "destination_port": destination_port_col,
        "user_agent": user_agent_col,
        "host": host_col,
        "user": user_col,
    }

    df_normalized, events = normalize_dataframe(df, mapping=mapping, source="dashboard_upload")

    temp_path = os.path.join(BASE_DIR, "data", "user_uploaded.csv")
    os.makedirs(os.path.dirname(temp_path), exist_ok=True)
    df_normalized.to_csv(temp_path, index=False)

    try:
        alerts, _ = analyze_logs(df_normalized, anomaly_threshold=threshold)
        upsert_events(events)
        alert_records = [
            AlertRecord(**alert, source="dashboard_upload")
            for alert in alerts
        ]
        upsert_alerts(alert_records)
        st.session_state["user_alerts"] = alerts
        st.sidebar.success(f"{len(alerts)} alerts generated")
    except Exception as error:
        st.error(f"Detection error: {error}")
        st.stop()

if uploaded_file and st.session_state["user_alerts"]:
    alerts = st.session_state["user_alerts"]
else:
    alerts = get_alerts()

if not alerts:
    st.info(
        "Awaiting data. Please upload a CSV file from the sidebar to start analysis."
    )
    st.stop()

metrics = get_alert_metrics()
entity_risk = build_entity_risk(alerts)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Active Alerts", metrics["total"])
col2.metric(
    "Critical Threats",
    metrics["critical"],
    "Immediate Action Req." if metrics["critical"] > 0 else None,
    delta_color="inverse",
)
col3.metric("High Severity", metrics["high"])
col4.metric("Avg ML Anomaly Score", round(metrics["average_anomaly"], 3))

st.markdown("---")

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "Analytics Overview",
        "Alert Triage Queue",
        "Attack Stories (Correlation)",
        "Entity Risk",
    ]
)

with tab1:
    st.subheader("Threat Landscape Overview")
    df_alerts = pd.DataFrame(alerts)

    if not df_alerts.empty:
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            if "severity" in df_alerts.columns:
                fig_sev = px.pie(
                    df_alerts,
                    names="severity",
                    title="Alerts by Severity",
                    hole=0.4,
                    color_discrete_map={
                        "CRITICAL": "#FF3366",
                        "HIGH": "#FF9933",
                        "MEDIUM": "#FFCC00",
                        "LOW": "#33CCFF",
                    },
                )
                fig_sev.update_layout(
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                )
                st.plotly_chart(fig_sev, use_container_width=True)

        with chart_col2:
            if "mitre" in df_alerts.columns:
                all_mitre = [
                    technique
                    for technique_list in df_alerts["mitre"].dropna()
                    for technique in technique_list
                ]
                if all_mitre:
                    mitre_counts = pd.Series(all_mitre).value_counts().reset_index()
                    mitre_counts.columns = ["Tactic", "Count"]
                    fig_mitre = px.bar(
                        mitre_counts,
                        x="Count",
                        y="Tactic",
                        orientation="h",
                        title="MITRE ATT&CK Tactics",
                        color="Count",
                        color_continuous_scale="Reds",
                    )
                    fig_mitre.update_layout(
                        plot_bgcolor="rgba(0,0,0,0)",
                        paper_bgcolor="rgba(0,0,0,0)",
                        yaxis={"categoryorder": "total ascending"},
                    )
                    st.plotly_chart(fig_mitre, use_container_width=True)

        suppressed_count = sum(1 for alert in alerts if alert.get("suppressed"))
        if suppressed_count:
            st.caption(
                f"{suppressed_count} alerts are currently suppressed by local tuning rules in config/suppressions.json."
            )

with tab2:
    st.subheader("Active Investigation Queue")

    filt_col1, filt_col2, filt_col3, filt_col4 = st.columns(4)
    sort_option = filt_col1.selectbox("Sort Timeline", ["Latest First", "Oldest First"])
    severity_filter = filt_col2.multiselect(
        "Filter Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=[]
    )
    status_filter = filt_col3.multiselect(
        "Filter Status", ["OPEN", "INVESTIGATING", "CLOSED"], default=[]
    )
    suppression_filter = filt_col4.selectbox(
        "Suppression View",
        ["Active Only", "Include Suppressed", "Suppressed Only"],
    )

    filtered_alerts = sorted(
        alerts, key=parse_time, reverse=(sort_option == "Latest First")
    )
    final_alerts = []
    for alert in filtered_alerts:
        if severity_filter and alert.get("severity", "").upper() not in severity_filter:
            continue
        if status_filter and alert.get("status", "OPEN").upper() not in status_filter:
            continue
        is_suppressed = bool(alert.get("suppressed"))
        if suppression_filter == "Active Only" and is_suppressed:
            continue
        if suppression_filter == "Suppressed Only" and not is_suppressed:
            continue
        final_alerts.append(alert)

    for alert in final_alerts:
        severity = alert.get("severity", "UNKNOWN")
        timestamp = alert.get("timestamp", "Unknown Time")
        process = alert.get("process", "Unknown Process")
        suppressed = alert.get("suppressed", False)

        header_title = f"{severity} | {process} | {time_ago(timestamp)}"
        if severity == "CRITICAL":
            header_title = "HOT | " + header_title
        if suppressed:
            header_title = "SUPPRESSED | " + header_title

        with st.expander(header_title):
            st.markdown(
                f"**Severity:** {severity_badge(severity)} &nbsp;&nbsp;|&nbsp;&nbsp; "
                f"**Timestamp:** `{timestamp}`",
                unsafe_allow_html=True,
            )
            st.caption(
                f"Fingerprint: `{alert.get('fingerprint', '')}` | Categories: {', '.join(alert.get('categories', [])) or 'none'}"
            )
            if suppressed:
                st.warning(
                    f"Suppressed by tuning rule: {alert.get('suppression_reason', 'No reason provided.')}"
                )

            det_col1, det_col2 = st.columns([2, 1])
            with det_col1:
                st.markdown("#### Explainability Context")
                st.write("**Detection Reasons:**")
                for reason in alert.get("reasons", []):
                    st.markdown(f"- {reason}")

                st.write("**Engine Explanation:**")
                for explanation in alert.get("explanations", []):
                    st.markdown(f"- *{explanation}*")

            with det_col2:
                st.markdown("#### Engine Metrics")
                if alert.get("anomaly_score") is not None:
                    score = alert.get("anomaly_score", 0)
                    st.metric(
                        "ML Anomaly Score",
                        round(score, 3),
                        anomaly_label(score),
                        delta_color="off",
                    )

                st.write("**Confidence:**", alert.get("confidence", "N/A"))
                st.write("**Entity Risk Score:**", alert.get("entity_risk_score", "N/A"))
                st.write("**MITRE Chain:**")
                for technique in alert.get("mitre", []):
                    st.code(technique)

    if uploaded_file and final_alerts:
        st.markdown("---")
        df_export = pd.DataFrame(final_alerts)
        st.download_button(
            "Download Triaged Alerts (CSV)",
            df_export.to_csv(index=False),
            file_name="verdict_alerts.csv",
            mime="text/csv",
            type="primary",
        )

with tab3:
    st.subheader("Correlated Attack Timelines")
    st.markdown(
        "The correlation engine groups isolated events into broader attack narratives."
    )

    stories = correlate_alerts(alerts)

    if not stories:
        st.success("No correlated attack chains found in the current dataset.")
    else:
        for story in stories:
            with st.container():
                st.markdown(f"### Target Process: `{story['process']}`")
                sc1, sc2 = st.columns(2)
                sc1.metric("Events in Chain", story["event_count"])
                sc2.metric("Cumulative Threat Score", story["score"])
                st.caption(
                    f"Story type: {story['story_type']} | Categories: {', '.join(story.get('categories', [])) or 'none'}"
                )

                st.markdown("#### Execution Timeline")
                for event in story["timeline"]:
                    st.info(
                        f"**{time_ago(event.get('timestamp'))}** -> {event.get('process')} \n\n"
                        f"*Matched:* {', '.join(event.get('reasons', []))}"
                    )

                st.markdown("#### MITRE Progression")
                st.markdown(" -> ".join([f"`{m}`" for m in story["mitre_chain"]]))
                st.markdown("---")

with tab4:
    st.subheader("Entity Risk Ranking")
    if not entity_risk:
        st.info("No entity risk data available yet.")
    else:
        risk_df = pd.DataFrame(entity_risk)
        st.dataframe(risk_df, use_container_width=True, hide_index=True)

        top_entities = risk_df.head(10)
        fig_entities = px.bar(
            top_entities,
            x="entity_value",
            y="risk_score",
            color="entity_type",
            title="Top Risky Entities",
        )
        fig_entities.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_entities, use_container_width=True)
