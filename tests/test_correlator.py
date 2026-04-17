from engine.correlator import correlate_alerts


def test_correlator_classifies_macro_execution_story():
    alerts = [
        {
            "timestamp": "2026-04-17 10:00:00",
            "process": "powershell.exe",
            "host": "host-1",
            "user": "alice",
            "score": 7,
            "mitre": ["T1059"],
            "reasons": [
                "Encoded PowerShell command detected",
                "Suspicious parent-child relationship (winword -> powershell)",
            ],
            "explanations": ["macro"],
            "categories": ["execution"],
        },
        {
            "timestamp": "2026-04-17 10:03:00",
            "process": "powershell.exe",
            "host": "host-1",
            "user": "alice",
            "score": 4,
            "mitre": ["T1071.001"],
            "reasons": ["Office spawning PowerShell", "Connection to external IP"],
            "explanations": ["network"],
            "categories": ["execution", "network"],
        },
    ]

    stories = correlate_alerts(alerts)

    assert len(stories) == 1
    assert stories[0]["story_type"] == "Macro Execution To Command And Control"
