RULES = {

    "encoded_powershell": {
        "description": "Encoded PowerShell command detected",
        "mitre": ["T1059"],
        "severity": 3,
        "explainability": "Attackers use Base64-encoded PowerShell commands to obfuscate malicious scripts and evade detection.",
        "check": lambda row: "powershell" in str(row.get("process", "")).lower()
                             and "-enc" in str(row.get("command_line", "")).lower()
    },

    "suspicious_parent": {
        "description": "Suspicious parent-child relationship (winword -> powershell)",
        "mitre": ["T1204"],
        "severity": 2,
        "explainability": "Microsoft Word spawning PowerShell is highly unusual and often indicates a malicious macro execution.",
        "check": lambda row: str(row.get("parent_process", "")).lower() == "winword.exe"
                             and "powershell" in str(row.get("process", "")).lower()
    },

    "external_ip": {
        "description": "Connection to external IP",
        "mitre": ["T1046"],
        "severity": 1,
        "explainability": "Outbound connections to public IPs may indicate communication with external servers or C2 infrastructure.",
        "check": lambda row: not str(row.get("ip", "")).startswith(("192.", "10."))
    },

    "lolbas_certutil_download": {
        "description": "Certutil used to download remote payload",
        "mitre": ["T1105"],
        "severity": 4,
        "explainability": "Certutil is abused by attackers to download malicious payloads using built-in Windows tools (LOLBAS technique).",
        "check": lambda row: "certutil" in str(row.get("process", "")).lower()
                             and "-urlcache" in str(row.get("command_line", "")).lower()
    },

    "injected_process_network": {
        "description": "Unusual process making network connection",
        "mitre": ["T1055"],
        "severity": 4,
        "explainability": "Processes like Notepad or Paint typically do not make network connections—this suggests possible code injection.",
        "check": lambda row: str(row.get("process", "")).lower() in ["notepad.exe", "mspaint.exe"]
                             and int(row.get("destination_port", 0)) in [80, 443, 4444]
    },

    "registry_persistence": {
        "description": "Registry Run key persistence detected",
        "mitre": ["T1547.001"],
        "severity": 3,
        "explainability": "Malware often modifies registry run keys to maintain persistence across system reboots.",
        "check": lambda row: "reg.exe" in str(row.get("process", "")).lower()
                             and "currentversion\\run" in str(row.get("command_line", "")).lower()
    },

    "temp_execution": {
        "description": "Execution from Temp directory",
        "mitre": ["T1036"],
        "severity": 3,
        "explainability": "Malware commonly executes from temporary directories to avoid detection and bypass permissions.",
        "check": lambda row: "\\temp\\" in str(row.get("command_line", "")).lower()
    },

    "suspicious_user_agent": {
        "description": "Suspicious User-Agent detected",
        "mitre": ["T1071.001"],
        "severity": 2,
        "explainability": "Malware often uses default HTTP libraries like python-requests or curl instead of real browser identifiers.",
        "check": lambda row: any(x in str(row.get("user_agent", "")).lower()
                                for x in ["python-requests", "curl", "winhttp"])
    }
}
