import pandas as pd

from database import init_database, upsert_alerts, upsert_events
from engine.correlator import correlate_alerts
from engine.entity_risk import build_entity_risk
from engine.stream_processor import stream_logs
from ingestion.normalize import normalize_dataframe
from models import AlertRecord
from output.alert_formatter import format_alert
from output.json_writer import save_alerts


def main():
    init_database()
    print("Starting Verdict stream...\n")

    all_alerts = []

    for alerts, rows in stream_logs("data/sample_logs.csv"):
        if alerts:
            rows_df = pd.DataFrame(rows)
            _, events = normalize_dataframe(rows_df, source="sample_stream")
            upsert_events(events)

            alert_records = [
                AlertRecord(**alert, source="sample_stream")
                for alert in alerts
            ]
            upsert_alerts(alert_records)

            for alert in alerts:
                all_alerts.append(alert)
                format_alert(alert)

            save_alerts(alerts, rows)
        else:
            print("No threat detected...\n")

    print("\nATTACK STORIES DETECTED:\n")
    stories = correlate_alerts(all_alerts)
    risky_entities = build_entity_risk(all_alerts)[:5]

    if not stories:
        print("No correlated attack stories found.\n")
    else:
        for story in stories:
            print(f"Process: {story['process']}")
            print(f"Story Type: {story['story_type']}")
            print(f"Events: {story['event_count']}")
            print(f"MITRE Chain: {story['mitre_chain']}")
            print(f"Threat Score: {story['score']}")
            print("-" * 40)

    if risky_entities:
        print("\nTOP RISKY ENTITIES:\n")
        for entity in risky_entities:
            print(
                f"{entity['entity_type']}: {entity['entity_value']} | "
                f"Risk: {entity['risk_score']} | Alerts: {entity['alert_count']}"
            )


if __name__ == "__main__":
    main()
