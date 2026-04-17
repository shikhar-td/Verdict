import pandas as pd

from models import NormalizedEvent


OPTIONAL_FIELDS = {
    "parent_process": "",
    "destination_port": 0,
    "user_agent": "",
    "host": "",
    "user": "",
}


def guess_column(columns, keywords):
    for column in columns:
        lowered = column.lower()
        for keyword in keywords:
            if keyword in lowered:
                return column
    return None


def build_default_mapping(columns):
    return {
        "process": guess_column(columns, ["process", "image", "exe"]),
        "command_line": guess_column(columns, ["command", "cmd"]),
        "ip": guess_column(columns, ["ip", "dest"]),
        "timestamp": guess_column(columns, ["time", "timestamp"]),
        "parent_process": guess_column(columns, ["parent_process", "parent", "pprocess"]),
        "destination_port": guess_column(columns, ["destination_port", "dest_port", "port"]),
        "user_agent": guess_column(columns, ["user_agent", "agent"]),
        "host": guess_column(columns, ["host", "computer", "device"]),
        "user": guess_column(columns, ["user", "account"]),
    }


def _series_or_default(df, column_name, default_value):
    if column_name and column_name in df.columns:
        return df[column_name]
    return pd.Series([default_value] * len(df), index=df.index)


def normalize_dataframe(df, mapping=None, source="csv"):
    if mapping is None:
        mapping = build_default_mapping(df.columns.tolist())

    required_fields = ["process", "command_line", "ip", "timestamp"]
    missing_required = [field for field in required_fields if not mapping.get(field)]
    if missing_required:
        raise ValueError(f"Missing required mapping fields: {', '.join(missing_required)}")

    normalized_df = pd.DataFrame(
        {
            "process": _series_or_default(df, mapping.get("process"), "").fillna("").astype(str),
            "command_line": _series_or_default(df, mapping.get("command_line"), "").fillna("").astype(str),
            "ip": _series_or_default(df, mapping.get("ip"), "").fillna("").astype(str),
            "timestamp": pd.to_datetime(
                _series_or_default(df, mapping.get("timestamp"), ""), errors="coerce"
            ).astype(str),
            "parent_process": _series_or_default(df, mapping.get("parent_process"), "").fillna("").astype(str),
            "destination_port": pd.to_numeric(
                _series_or_default(df, mapping.get("destination_port"), 0), errors="coerce"
            ).fillna(0).astype(int),
            "user_agent": _series_or_default(df, mapping.get("user_agent"), "").fillna("").astype(str),
            "host": _series_or_default(df, mapping.get("host"), "").fillna("").astype(str),
            "user": _series_or_default(df, mapping.get("user"), "").fillna("").astype(str),
        }
    )

    events = []
    for index, row in normalized_df.iterrows():
        raw_event = df.iloc[index].to_dict()
        event = NormalizedEvent(
            event_id=f"{row['timestamp']}_{row['process']}_{index}",
            timestamp=row["timestamp"],
            process=row["process"],
            command_line=row["command_line"],
            ip=row["ip"],
            parent_process=row["parent_process"],
            destination_port=int(row["destination_port"]),
            user_agent=row["user_agent"],
            host=row["host"],
            user=row["user"],
            source=source,
            raw_event=raw_event,
        )
        events.append(event)

    return normalized_df, events
