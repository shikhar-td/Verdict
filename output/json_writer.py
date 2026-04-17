import os
from datetime import datetime

from output.alert_formatter import get_confidence, get_severity


def convert_to_json(alert, original_row):
    timestamp = original_row.get("timestamp", str(datetime.now()))

    return {
        "id": alert.get("id", f"{timestamp}_{alert['process']}"),
        "timestamp": timestamp,
        "process": alert["process"],
        "severity": get_severity(alert["score"]),
        "confidence": get_confidence(alert["score"]),
        "mitre": alert["mitre"],
        "reasons": alert["reasons"],
        "explanations": alert["explanations"],
        "score": alert["score"],
        "status": alert.get("status", "OPEN"),
        "priority": alert.get("priority", get_severity(alert["score"])),
        "analyst_notes": alert.get("analyst_notes", ""),
        "anomaly_score": alert.get("anomaly_score"),
    }


def save_alerts(alerts, rows):
    import json

    file_path = "output/alerts.json"

    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            try:
                existing_alerts = json.load(file)
            except Exception:
                existing_alerts = []
    else:
        existing_alerts = []

    alerts_by_id = {alert["id"]: alert for alert in existing_alerts if "id" in alert}

    for alert, row in zip(alerts, rows):
        json_alert = convert_to_json(alert, row)
        alerts_by_id[json_alert["id"]] = json_alert

    deduped_alerts = sorted(
        alerts_by_id.values(),
        key=lambda alert: (alert.get("timestamp", ""), alert.get("process", "")),
    )

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(deduped_alerts, file, indent=4)

    print(f"Total alerts stored: {len(deduped_alerts)}")
