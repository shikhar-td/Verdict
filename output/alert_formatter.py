def get_severity(score):
    if score >= 6:
        return "CRITICAL"
    if score >= 4:
        return "HIGH"
    if score >= 2:
        return "MEDIUM"
    return "LOW"


def get_confidence(score):
    return round(min(score / 6, 1.0), 2)


def format_alert(alert):
    severity = get_severity(alert["score"])
    confidence = get_confidence(alert["score"])

    print("\n" + "=" * 50)
    print(f"ALERT: {severity}")
    print("=" * 50)
    print(f"Process: {alert['process']}")

    print("\nReasons:")
    for reason in alert["reasons"]:
        print(f"- {reason}")

    print("\nExplanation:")
    for explanation in alert["explanations"]:
        print(f"- {explanation}")

    print("\nMITRE Techniques:")
    for technique in alert["mitre"]:
        print(f"- {technique}")

    print(f"\nConfidence Score: {confidence}")
    print("=" * 50 + "\n")
