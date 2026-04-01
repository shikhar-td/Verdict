from datetime import datetime, timedelta


def parse_time_safe(alert):
    try:
        return datetime.strptime(alert.get("timestamp"), "%Y-%m-%d %H:%M:%S")
    except:
        return datetime.min


def correlate_alerts(alerts, window_minutes=2):
    
    alerts = [a for a in alerts if a.get("timestamp")]

    alerts = sorted(alerts, key=parse_time_safe)

    grouped = []
    current_group = []

    for alert in alerts:

        if not current_group:
            current_group.append(alert)
            continue

        last_alert = current_group[-1]

        time_diff = parse_time_safe(alert) - parse_time_safe(last_alert)

        if (
            alert["process"] == last_alert["process"]
            and time_diff <= timedelta(minutes=window_minutes)
        ):
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
        total_score = 0

        for alert in group:
            mitre_chain.update(alert.get("mitre", []))
            reasons.extend(alert.get("reasons", []))
            explanations.extend(alert.get("explanations", []))
            total_score += alert.get("score", 0)

        stories.append({
            "process": group[0]["process"],
            "event_count": len(group),
            "mitre_chain": list(mitre_chain),
            "reasons": list(set(reasons)),
            "explanations": list(set(explanations)),
            "score": total_score,
            "timeline": group
        })

    return stories
