import time

import pandas as pd

from engine.analyzer import analyze_logs


def stream_logs(file_path, delay=2):
    df = pd.read_csv(file_path)

    for i in range(len(df)):
        cumulative_df = df.iloc[: i + 1].copy()
        alerts, rows = analyze_logs(cumulative_df)
        current_row = rows[-1]

        current_event_id = f"{current_row.get('timestamp')}_{current_row.get('process')}_{i}"
        current_alerts = [
            alert for alert in alerts if alert.get("id") == current_event_id
        ]

        yield current_alerts, [current_row]

        time.sleep(delay)
