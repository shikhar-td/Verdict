import json
import os
import sqlite3
from pathlib import Path

from models import AlertRecord, NormalizedEvent


BASE_DIR = Path(__file__).resolve().parent


def get_db_path():
    env_path = os.getenv("VERDICT_DB_PATH")
    if env_path:
        return Path(env_path)
    return BASE_DIR / "data" / "verdict.db"


def get_connection():
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                process TEXT,
                command_line TEXT,
                ip TEXT,
                parent_process TEXT,
                destination_port INTEGER,
                user_agent TEXT,
                host TEXT,
                user TEXT,
                source TEXT,
                raw_event TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                process TEXT,
                severity TEXT,
                confidence REAL,
                mitre TEXT,
                reasons TEXT,
                explanations TEXT,
                score INTEGER,
                status TEXT,
                priority TEXT,
                analyst_notes TEXT,
                anomaly_score REAL,
                source TEXT,
                assignee TEXT,
                false_positive_reason TEXT,
                host TEXT,
                user TEXT,
                ip TEXT,
                categories TEXT,
                fingerprint TEXT,
                suppressed INTEGER,
                suppression_reason TEXT,
                entity_risk_score INTEGER
            )
            """
        )
        _ensure_column(connection, "alerts", "host", "TEXT", "''")
        _ensure_column(connection, "alerts", "user", "TEXT", "''")
        _ensure_column(connection, "alerts", "ip", "TEXT", "''")
        _ensure_column(connection, "alerts", "categories", "TEXT", "'[]'")
        _ensure_column(connection, "alerts", "fingerprint", "TEXT", "''")
        _ensure_column(connection, "alerts", "suppressed", "INTEGER", "0")
        _ensure_column(connection, "alerts", "suppression_reason", "TEXT", "''")
        _ensure_column(connection, "alerts", "entity_risk_score", "INTEGER", "0")


def _ensure_column(connection, table_name, column_name, column_type, default_sql):
    existing_columns = {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    if column_name in existing_columns:
        return
    connection.execute(
        f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type} DEFAULT {default_sql}"
    )


def upsert_events(events):
    if not events:
        return

    with get_connection() as connection:
        connection.executemany(
            """
            INSERT INTO events (
                event_id, timestamp, process, command_line, ip, parent_process,
                destination_port, user_agent, host, user, source, raw_event
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                timestamp=excluded.timestamp,
                process=excluded.process,
                command_line=excluded.command_line,
                ip=excluded.ip,
                parent_process=excluded.parent_process,
                destination_port=excluded.destination_port,
                user_agent=excluded.user_agent,
                host=excluded.host,
                user=excluded.user,
                source=excluded.source,
                raw_event=excluded.raw_event
            """,
            [
                (
                    event.event_id,
                    event.timestamp,
                    event.process,
                    event.command_line,
                    event.ip,
                    event.parent_process,
                    event.destination_port,
                    event.user_agent,
                    event.host,
                    event.user,
                    event.source,
                    json.dumps(event.raw_event),
                )
                for event in events
            ],
        )


def upsert_alerts(alerts):
    if not alerts:
        return

    with get_connection() as connection:
        connection.executemany(
            """
            INSERT INTO alerts (
                id, timestamp, process, severity, confidence, mitre, reasons,
                explanations, score, status, priority, analyst_notes,
                anomaly_score, source, assignee, false_positive_reason, host, user,
                ip, categories, fingerprint, suppressed, suppression_reason,
                entity_risk_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                timestamp=excluded.timestamp,
                process=excluded.process,
                severity=excluded.severity,
                confidence=excluded.confidence,
                mitre=excluded.mitre,
                reasons=excluded.reasons,
                explanations=excluded.explanations,
                score=excluded.score,
                status=excluded.status,
                priority=excluded.priority,
                analyst_notes=excluded.analyst_notes,
                anomaly_score=excluded.anomaly_score,
                source=excluded.source,
                assignee=excluded.assignee,
                false_positive_reason=excluded.false_positive_reason,
                host=excluded.host,
                user=excluded.user,
                ip=excluded.ip,
                categories=excluded.categories,
                fingerprint=excluded.fingerprint,
                suppressed=excluded.suppressed,
                suppression_reason=excluded.suppression_reason,
                entity_risk_score=excluded.entity_risk_score
            """,
            [
                (
                    alert.id,
                    alert.timestamp,
                    alert.process,
                    alert.severity,
                    alert.confidence,
                    json.dumps(alert.mitre),
                    json.dumps(alert.reasons),
                    json.dumps(alert.explanations),
                    alert.score,
                    alert.status,
                    alert.priority,
                    alert.analyst_notes,
                    alert.anomaly_score,
                    alert.source,
                    alert.assignee,
                    alert.false_positive_reason,
                    alert.host,
                    alert.user,
                    alert.ip,
                    json.dumps(alert.categories),
                    alert.fingerprint,
                    int(alert.suppressed),
                    alert.suppression_reason,
                    alert.entity_risk_score,
                )
                for alert in alerts
            ],
        )


def get_alerts():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC, process ASC"
        ).fetchall()

    alerts = []
    for row in rows:
        alert = dict(row)
        alert["mitre"] = json.loads(alert["mitre"]) if alert["mitre"] else []
        alert["reasons"] = json.loads(alert["reasons"]) if alert["reasons"] else []
        alert["explanations"] = (
            json.loads(alert["explanations"]) if alert["explanations"] else []
        )
        alert["categories"] = json.loads(alert["categories"]) if alert["categories"] else []
        alert["suppressed"] = bool(alert["suppressed"])
        alerts.append(alert)

    return alerts


def get_alert_metrics():
    alerts = get_alerts()
    total = len(alerts)
    critical = sum(1 for alert in alerts if alert.get("severity") == "CRITICAL")
    high = sum(1 for alert in alerts if alert.get("severity") == "HIGH")
    anomaly_scores = [
        alert.get("anomaly_score")
        for alert in alerts
        if alert.get("anomaly_score") is not None
    ]
    average_anomaly = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "average_anomaly": average_anomaly,
    }


def clear_tables():
    with get_connection() as connection:
        connection.execute("DELETE FROM events")
        connection.execute("DELETE FROM alerts")
