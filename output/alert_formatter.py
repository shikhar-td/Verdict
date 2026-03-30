def get_severity(score):
    if score >= 6:
        return "CRITICAL"
    elif score >= 4:
        return "HIGH"
    elif score >= 2:
        return "MEDIUM"
    else:
        return "LOW"


def get_confidence(score):
    return round(min(score / 6, 1.0), 2)


def format_alert(alert):
    severity = get_severity(alert["score"])
    confidence = get_confidence(alert["score"])

    print("\n" + "="*50)
    print(f"🚨 ALERT: {severity}")
    print("="*50)

    print(f"Process: {alert['process']}")

    print("\n🔍 Reasons:")
    for r in alert["reasons"]:
        print(f"- {r}")

    print("\n🧠 Explanation:")
    for exp in alert["explanations"]:
        print(f"- {exp}")

    print("\n🎯 MITRE Techniques:")
    for m in alert["mitre"]:
        print(f"- {m}")

    print(f"\n📊 Confidence Score: {confidence}")
    print("="*50 + "\n")
