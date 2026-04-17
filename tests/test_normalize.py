import pandas as pd

from ingestion.normalize import normalize_dataframe


def test_normalize_dataframe_preserves_optional_fields():
    df = pd.DataFrame(
        [
            {
                "ts": "2026-04-17 10:00:00",
                "proc": "powershell.exe",
                "cmd": "powershell -enc test",
                "dest_ip": "8.8.8.8",
                "parent": "winword.exe",
                "port": 443,
                "agent": "python-requests",
                "host_name": "host-1",
                "user_name": "alice",
            }
        ]
    )

    normalized_df, events = normalize_dataframe(
        df,
        mapping={
            "process": "proc",
            "command_line": "cmd",
            "ip": "dest_ip",
            "timestamp": "ts",
            "parent_process": "parent",
            "destination_port": "port",
            "user_agent": "agent",
            "host": "host_name",
            "user": "user_name",
        },
        source="test",
    )

    assert normalized_df.iloc[0]["parent_process"] == "winword.exe"
    assert normalized_df.iloc[0]["destination_port"] == 443
    assert normalized_df.iloc[0]["user_agent"] == "python-requests"
    assert normalized_df.iloc[0]["host"] == "host-1"
    assert normalized_df.iloc[0]["user"] == "alice"
    assert events[0].source == "test"
