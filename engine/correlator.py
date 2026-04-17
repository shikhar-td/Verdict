from datetime import datetime, timedelta


def parse_time_safe(alert):
    try:
        return datetime.strptime(alert.get("timestamp"), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.min


def classify_story(group):
    reasons = {
        reason
        for alert in group
        for reason in alert.get("reasons", [])
    }

    if {
        "Encoded PowerShell command detected",
        "Suspicious parent-child relationship (winword -> powershell)",
        "Office spawning PowerShell",
    }.intersection(reasons):
        if "Suspicious User-Agent detected" in reasons or "Connection to external IP" in reasons:
            return "Macro Execution To Command And Control"

    if "Certutil used to download remote payload" in reasons and "Execution from Temp directory" in reasons:
        return "Payload Retrieval And Execution"

    if "Registry Run key persistence detected" in reasons:
        return "Persistence Establishment"

    if "Unusual process making network connection" in reasons:
        return "Potential Process Injection"

    return "Suspicious Activity Cluster"


def correlate_alerts(alerts, window_minutes=5):
    alerts = [alert for alert in alerts if alert.get("timestamp")]
    alerts = sorted(alerts, key=parse_time_safe)

    grouped = []
    current_group = []

    for alert in alerts:
        if alert.get("suppressed"):
            continue

        if not current_group:
            current_group.append(alert)
            continue

        last_alert = current_group[-1]
        time_diff = parse_time_safe(alert) - parse_time_safe(last_alert)
        same_process = alert.get("process") == last_alert.get("process")
        same_host = (alert.get("host") or "") == (last_alert.get("host") or "")
        same_user = (alert.get("user") or "") == (last_alert.get("user") or "")

        if same_process and same_host and same_user and time_diff <= timedelta(minutes=window_minutes):
            current_group.append(alert)
        else:
            grouped.append(current_group)
            current_group = [alert]

    if current_group:
        grouped.append(current_group)

    stories = []
    for group in grouped:
        if len(group) < 2:
            continue

        mitre_chain = set()
        reasons = []
        explanations = []
        categories = set()
        total_score = 0

        for alert in group:
            mitre_chain.update(alert.get("mitre", []))
            reasons.extend(alert.get("reasons", []))
            explanations.extend(alert.get("explanations", []))
            categories.update(alert.get("categories", []))
            total_score += alert.get("score", 0)

        stories.append(
            {
                "process": group[0].get("process"),
                "host": group[0].get("host", ""),
                "user": group[0].get("user", ""),
                "event_count": len(group),
                "mitre_chain": list(mitre_chain),
                "reasons": list(set(reasons)),
                "explanations": list(set(explanations)),
                "categories": sorted(categories),
                "score": total_score,
                "story_type": classify_story(group),
                "timeline": group,
            }
        )

    return stories
