import json
from pathlib import Path


SUPPRESSIONS_PATH = Path(__file__).resolve().parent.parent / "config" / "suppressions.json"


def load_suppressions():
    if not SUPPRESSIONS_PATH.exists():
        return []

    with open(SUPPRESSIONS_PATH, "r", encoding="utf-8") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            return []

    return data if isinstance(data, list) else []


def match_suppression(alert, suppressions):
    process = str(alert.get("process", "")).lower()
    reasons = {reason.lower() for reason in alert.get("reasons", [])}
    severity = str(alert.get("severity", "")).upper()

    for suppression in suppressions:
        suppression_process = str(suppression.get("process", "")).lower()
        suppression_reason = str(suppression.get("reason", "")).lower()
        suppression_severity = str(suppression.get("severity", "")).upper()

        if suppression_process and suppression_process != process:
            continue
        if suppression_reason and suppression_reason not in reasons:
            continue
        if suppression_severity and suppression_severity != severity:
            continue
        return True, suppression.get("note", "Suppressed by local tuning rule.")

    return False, ""
