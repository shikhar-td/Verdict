from collections import defaultdict


def build_entity_risk(alerts):
    entities = defaultdict(
        lambda: {
            "entity_type": "",
            "entity_value": "",
            "risk_score": 0,
            "alert_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "top_reasons": defaultdict(int),
        }
    )

    for alert in alerts:
        severity = str(alert.get("severity", "")).upper()
        base_score = int(alert.get("score", 0))
        entity_targets = [
            ("process", alert.get("process")),
            ("host", alert.get("host")),
            ("user", alert.get("user")),
        ]

        for entity_type, entity_value in entity_targets:
            if not entity_value:
                continue

            key = (entity_type, entity_value)
            entry = entities[key]
            entry["entity_type"] = entity_type
            entry["entity_value"] = entity_value
            entry["risk_score"] += base_score
            entry["alert_count"] += 1

            if severity == "CRITICAL":
                entry["critical_count"] += 1
                entry["risk_score"] += 3
            elif severity == "HIGH":
                entry["high_count"] += 1
                entry["risk_score"] += 1

            for reason in alert.get("reasons", []):
                entry["top_reasons"][reason] += 1

    ranked = []
    for entry in entities.values():
        top_reasons = sorted(
            entry["top_reasons"].items(), key=lambda item: item[1], reverse=True
        )[:3]
        ranked.append(
            {
                "entity_type": entry["entity_type"],
                "entity_value": entry["entity_value"],
                "risk_score": entry["risk_score"],
                "alert_count": entry["alert_count"],
                "critical_count": entry["critical_count"],
                "high_count": entry["high_count"],
                "top_reasons": [reason for reason, _ in top_reasons],
            }
        )

    return sorted(
        ranked,
        key=lambda item: (
            item["risk_score"],
            item["critical_count"],
            item["alert_count"],
            item["entity_value"],
        ),
        reverse=True,
    )
