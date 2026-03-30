import json
import os
from datetime import datetime
from output.alert_formatter import get_severity, get_confidence


def convert_to_json(alert, original_row):
    return {
        "id": f"{original_row.get('timestamp')}_{alert['process']}",

        "timestamp": original_row.get("timestamp", str(datetime.now())),
        "process": alert["process"],
        "severity": get_severity(alert["score"]),
        "confidence": get_confidence(alert["score"]),
        "mitre": alert["mitre"],
        "reasons": alert["reasons"],
        "explanations": alert["explanations"],

        # 🔥 IMPORTANT FOR CORRELATION
        "score": alert["score"],

        # Analyst workflow fields
        "status": "OPEN",
        "priority": get_severity(alert["score"]),
        "analyst_notes": ""
    }


def save_alerts(alerts, rows):
    file_path = "output/alerts.json"

    # Load existing alerts
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            try:
                existing_alerts = json.load(f)
            except:
                existing_alerts = []
    else:
        existing_alerts = []

    # Append new alerts
    for alert, row in zip(alerts, rows):
        existing_alerts.append(convert_to_json(alert, row))

    # Save updated alerts
    with open(file_path, "w") as f:
        json.dump(existing_alerts, f, indent=4)

    print(f"✅ Total alerts stored: {len(existing_alerts)}")
