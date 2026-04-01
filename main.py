from engine.stream_processor import stream_logs
from output.alert_formatter import format_alert
from output.json_writer import save_alerts
from engine.correlator import correlate_alerts


def main():
    print("🚀 Starting ExplainSOC Stream...\n")

    all_alerts = []

    for alerts, rows in stream_logs("data/sample_logs.csv"):

        if alerts:
    
            for alert, row in zip(alerts, rows):
                alert["timestamp"] = row.get("timestamp")

                
                all_alerts.append(alert)

                
                format_alert(alert)

            
            save_alerts(alerts, rows)

        else:
            print("No threat detected...\n")

    
    print("\n🔥 ATTACK STORIES DETECTED:\n")

    stories = correlate_alerts(all_alerts)

    if not stories:
        print("No correlated at500tack stories found.\n")
        return

    for story in stories:
        print(f"🚨 Process: {story['process']}")
        print(f"Events: {story['event_count']}")
        print(f"MITRE Chain: {story['mitre_chain']}")
        print(f"Threat Score: {story['score']}")
        print("-" * 40)


if __name__ == "__main__":
    main()

