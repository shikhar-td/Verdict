import pandas as pd
from detection.rules import RULES
from output.alert_formatter import get_severity, get_confidence

from sklearn.ensemble import IsolationForest


def analyze_logs(file_path, anomaly_threshold=-0.1):
    df = pd.read_csv(file_path)

    alerts = []



    df["cmd_length"] = df["command_line"].astype(str).apply(len)

    df["has_http"] = df["command_line"].astype(str).apply(
        lambda x: 1 if "http" in x.lower() else 0
    )

    df["has_exe"] = df["command_line"].astype(str).apply(
        lambda x: 1 if ".exe" in x.lower() else 0
    )

    df["is_external_ip"] = df["ip"].astype(str).apply(
        lambda x: 0 if x.startswith(("192.", "10.", "172.")) else 1
    )

    df["is_powershell"] = df["process"].astype(str).apply(
        lambda x: 1 if "powershell" in x.lower() else 0
    )

    features = df[
        ["cmd_length", "has_http", "has_exe", "is_external_ip", "is_powershell"]
    ]

    contamination = min(0.1, max(0.01, len(df) * 0.01))

    model = IsolationForest(
        contamination=contamination,
        random_state=42
    )

    model.fit(features)

    df["anomaly_score"] = model.decision_function(features)



    process_counts = df["process"].value_counts().to_dict()

    known_processes = set([
        "chrome.exe", "explorer.exe", "cmd.exe",
        "powershell.exe", "notepad.exe"
    ])



    for _, row in df.iterrows():
        try:

            reasons = []
            explanations = []
            mitre = set()
            score = 0

            process = str(row.get("process", "")).lower()
            cmd = str(row.get("command_line", "")).lower()
            ip = str(row.get("ip", ""))

            # 🔴 RULES
            for rule in RULES.values():
                try:
                    if rule["check"](row):
                        reasons.append(rule["description"])
                        mitre.update(rule["mitre"])
                        score += rule["severity"]

                        if "explainability" in rule:
                            explanations.append(rule["explainability"])
                except:
                    continue
        except Exception:
            continue  

        
        if len(cmd) > 150:
            reasons.append("Unusually long command detected")
            explanations.append("Long commands may indicate obfuscation.")
            score += 1

        if "http" in cmd and ".exe" in cmd:
            reasons.append("Executable download via URL")
            explanations.append("Executable download detected.")
            mitre.add("T1105")
            score += 2

        if process == "powershell.exe" and "winword.exe" in str(row.get("parent_process", "")).lower():
            reasons.append("Office spawning PowerShell")
            explanations.append("Macro-based attack behavior.")
            mitre.add("T1059")
            score += 2

        
        if row["anomaly_score"] < anomaly_threshold:
            reasons.append("ML anomaly detected")
            explanations.append("Behavior deviates from baseline patterns.")
            score += 1

        
        if process_counts.get(row.get("process"), 0) == 1:
            reasons.append("Rare process observed")
            explanations.append("This process appears only once.")
            score += 1

        if process and process not in known_processes:
            reasons.append("Unknown process execution")
            explanations.append("Unrecognized process.")
            score += 1

        if ip and not ip.startswith(("192.", "10.", "172.")):
            reasons.append("External IP communication")
            explanations.append("Connection to external IP.")
            score += 1

        
        if reasons:
            severity = get_severity(score)
            confidence = get_confidence(score)

            alerts.append({
                "process": row.get("process"),
                "reasons": list(set(reasons)),
                "explanations": list(set(explanations)),
                "mitre": list(mitre),
                "score": score,
                "severity": severity,
                "confidence": confidence,
                "status": "OPEN",
                "priority": severity,
                "analyst_notes": "",
                "anomaly_score": float(row.get("anomaly_score", 0))
            })

    return alerts, df.to_dict(orient="records")
