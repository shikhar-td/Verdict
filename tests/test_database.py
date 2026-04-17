import importlib

import database
from models import AlertRecord


def test_upsert_alerts_deduplicates_by_id(tmp_path, monkeypatch):
    monkeypatch.setenv("VERDICT_DB_PATH", str(tmp_path / "test_verdict.db"))
    importlib.reload(database)
    database.init_database()
    database.clear_tables()

    alert = AlertRecord(
        id="evt-1",
        timestamp="2026-04-17 00:00:00",
        process="powershell.exe",
        severity="HIGH",
        confidence=0.9,
        mitre=["T1059"],
        reasons=["Encoded PowerShell command detected"],
        explanations=["Suspicious encoded execution."],
        score=6,
        priority="HIGH",
    )

    updated_alert = alert.model_copy(update={"status": "CLOSED"})

    database.upsert_alerts([alert])
    database.upsert_alerts([updated_alert])

    alerts = database.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["status"] == "CLOSED"
