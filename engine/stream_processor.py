import time
import pandas as pd
from engine.analyzer import analyze_logs


def stream_logs(file_path, delay=2):
    df = pd.read_csv(file_path)

    for i in range(len(df)):
        single_row_df = df.iloc[[i]]
        
        # Save temp row
        temp_file = "data/temp_log.csv"
        single_row_df.to_csv(temp_file, index=False)

        alerts, rows = analyze_logs(temp_file)

        yield alerts, rows

        time.sleep(delay)
