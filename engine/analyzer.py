import hashlib

import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "scikit-learn is not installed in the active Python environment. "
        "Activate the project's virtual environment or install dependencies with "
        "'python -m pip install -r requirements.txt'."
    ) from exc

from detection.rules import RULES
from detection.suppressions import load_suppressions, match_suppression
from output.alert_formatter import get_confidence, get_severity


REQUIRED_COLUMNS = {
    "process": "",
    "command_line": "",
    "ip": "",
    "timestamp": "",
    "parent_process": "",
    "destination_port": 0,
    "user_agent": "",
    "host": "",
    "user": "",
}


def _load_dataframe(log_source):
    if isinstance(log_source, pd.DataFrame):
        df = log_source.copy()
    else:
        df = pd.read_csv(log_source)

    for column, default_value in REQUIRED_COLUMNS.items():
        if column not in df.columns:
            df[column] = default_value

    df["process"] = df["process"].fillna("").astype(str)
    df["command_line"] = df["command_line"].fillna("").astype(str)
    df["ip"] = df["ip"].fillna("").astype(str)
    df["timestamp"] = df["timestamp"].fillna("").astype(str)
    df["parent_process"] = df["parent_process"].fillna("").astype(str)
    df["user_agent"] = df["user_agent"].fillna("").astype(str)
    df["host"] = df["host"].fillna("").astype(str)
    df["user"] = df["user"].fillna("").astype(str)
    df["destination_port"] = pd.to_numeric(
        df["destination_port"], errors="coerce"
    ).fillna(0).astype(int)

    return df


def _build_fingerprint(process, parent_process, ip, reasons, categories):
    material = "|".join(
        [
            process.lower(),
            parent_process.lower(),
            ip,
            ",".join(sorted(reasons)),
            ",".join(sorted(categories)),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def analyze_logs(log_source, anomaly_threshold=-0.1):
    df = _load_dataframe(log_source)
    alerts = []

    df["cmd_length"] = df["command_line"].apply(len)
    df["has_http"] = df["command_line"].apply(lambda x: 1 if "http" in x.lower() else 0)
    df["has_exe"] = df["command_line"].apply(lambda x: 1 if ".exe" in x.lower() else 0)
    df["is_external_ip"] = df["ip"].apply(
        lambda x: 0 if x.startswith(("192.", "10.", "172.")) else 1
    )
    df["is_powershell"] = df["process"].apply(
        lambda x: 1 if "powershell" in x.lower() else 0
    )

    features = df[
        ["cmd_length", "has_http", "has_exe", "is_external_ip", "is_powershell"]
    ]

    contamination = min(0.1, max(0.01, len(df) * 0.01))
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(features)
    df["anomaly_score"] = model.decision_function(features)

    process_counts = df["process"].value_counts().to_dict()
    known_processes = {
        "chrome.exe",
        "explorer.exe",
        "cmd.exe",
        "powershell.exe",
        "notepad.exe",
    }
    suppressions = load_suppressions()

    for row_index, row in df.iterrows():
        reasons = []
        explanations = []
        mitre = set()
        categories = set()
        score = 0

        process = row["process"].lower()
        cmd = row["command_line"].lower()
        ip = row["ip"]
        timestamp = row["timestamp"]
        event_id = f"{timestamp}_{row['process']}_{row_index}"

        for rule in RULES.values():
            try:
                if rule["check"](row):
                    reasons.append(rule["description"])
                    mitre.update(rule["mitre"])
                    categories.add(rule.get("category", "general"))
                    score += rule["severity"]

                    if "explainability" in rule:
                        explanations.append(rule["explainability"])
            except Exception:
                continue

        if len(cmd) > 150:
            reasons.append("Unusually long command detected")
            explanations.append("Long commands may indicate obfuscation.")
            categories.add("defense_evasion")
            score += 1

        if "http" in cmd and ".exe" in cmd:
            reasons.append("Executable download via URL")
            explanations.append("Executable download detected.")
            mitre.add("T1105")
            categories.add("execution")
            score += 2

        if process == "powershell.exe" and "winword.exe" in row["parent_process"].lower():
            reasons.append("Office spawning PowerShell")
            explanations.append("Macro-based attack behavior.")
            mitre.add("T1059")
            categories.add("execution")
            score += 2

        if row["anomaly_score"] < anomaly_threshold:
            reasons.append("ML anomaly detected")
            explanations.append("Behavior deviates from baseline patterns.")
            categories.add("anomaly")
            score += 1

        if process_counts.get(row["process"], 0) == 1:
            reasons.append("Rare process observed")
            explanations.append("This process appears only once.")
            categories.add("anomaly")
            score += 1

        if process and process not in known_processes:
            reasons.append("Unknown process execution")
            explanations.append("Unrecognized process.")
            categories.add("execution")
            score += 1

        if ip and not ip.startswith(("192.", "10.", "172.")):
            reasons.append("External IP communication")
            explanations.append("Connection to external IP.")
            categories.add("network")
            score += 1

        if reasons:
            severity = get_severity(score)
            confidence = get_confidence(score)
            fingerprint = _build_fingerprint(
                row["process"],
                row["parent_process"],
                row["ip"],
                reasons,
                categories,
            )
            provisional_alert = {
                "id": event_id,
                "timestamp": timestamp,
                "process": row["process"],
                "host": row["host"],
                "user": row["user"],
                "ip": row["ip"],
                "reasons": list(set(reasons)),
                "explanations": list(set(explanations)),
                "mitre": list(mitre),
                "categories": sorted(categories),
                "score": score,
                "severity": severity,
                "confidence": confidence,
                "status": "OPEN",
                "priority": severity,
                "analyst_notes": "",
                "anomaly_score": float(row["anomaly_score"]),
                "fingerprint": fingerprint,
            }
            suppressed, suppression_reason = match_suppression(
                provisional_alert, suppressions
            )
            provisional_alert["suppressed"] = suppressed
            provisional_alert["suppression_reason"] = suppression_reason
            provisional_alert["false_positive_reason"] = ""
            provisional_alert["assignee"] = ""
            provisional_alert["entity_risk_score"] = score

            alerts.append(provisional_alert)

    return alerts, df.to_dict(orient="records")
