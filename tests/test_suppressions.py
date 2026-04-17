from detection.suppressions import match_suppression


def test_match_suppression_matches_process_reason_and_severity():
    alert = {
        "process": "chrome.exe",
        "severity": "MEDIUM",
        "reasons": ["Connection to external IP"],
    }
    suppressions = [
        {
            "process": "chrome.exe",
            "reason": "Connection to external IP",
            "severity": "MEDIUM",
            "note": "Expected browser traffic.",
        }
    ]

    suppressed, reason = match_suppression(alert, suppressions)

    assert suppressed is True
    assert reason == "Expected browser traffic."
