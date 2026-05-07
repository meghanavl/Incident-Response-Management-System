# file: evidence_collection/log_parser.py

import time
from collections import deque


class LogParser:

    def __init__(self):
        self.logs = []
        self.log_window = deque(maxlen=5)

    def stream_logs(self, scenario="random", delay=0.3):

        scenarios = {

            "bruteforce": [
                "LOGIN_FAILED user=admin ip=192.168.1.20",
                "LOGIN_FAILED user=admin ip=192.168.1.20",
                "LOGIN_FAILED user=admin ip=192.168.1.20",
                "LOGIN_FAILED user=root ip=10.0.0.5",
            ],

            "phishing": [
                "EMAIL_ATTACHMENT_EXECUTED file=invoice.exe",
                "EMAIL_ATTACHMENT_EXECUTED file=invoice.exe",
                "NORMAL_LOGIN user=john",
            ],

            "malware": [
                "POWERSHELL suspicious_script.ps1",
                "EMAIL_ATTACHMENT_EXECUTED file=payload.exe",
                "POWERSHELL suspicious_script.ps1",
            ],

            "exfiltration": [
                "POWERSHELL suspicious_script.ps1",
                "LARGE_OUTBOUND_TRANSFER size=2GB destination=185.22.10.5",
                "UNUSUAL_FTP_UPLOAD destination=external_server",
                "SUSPICIOUS_DATA_TRANSFER"
            ],

            "mixed": [
                "LOGIN_FAILED user=admin",
                "EMAIL_ATTACHMENT_EXECUTED file=invoice.exe",
                "POWERSHELL suspicious_script.ps1",
                "LARGE_OUTBOUND_TRANSFER size=1GB",
                "LOGIN_FAILED user=root",
            ]
        }

        logs_to_stream = scenarios.get(scenario, scenarios["mixed"])

        for log in logs_to_stream:
            self.logs.append(log)
            self.log_window.append(log)

            yield log
            time.sleep(delay)

    def analyze_stream(self):

        evidence = {
            "FailedLogins": 0,
            "SuspiciousEmail": 0,
            "PowerShellExec": 0,
            "BruteForcePattern": 0,
            "MalwareSequence": 0,
            "DataExfiltrationPattern": 0,

            "ExfiltrationRiskScore": 0,
            "ExfiltrationSeverity": "NONE"
        }

        # --------------------------------
        # BASIC INDICATORS
        # --------------------------------
        for log in self.logs:

            if "LOGIN_FAILED" in log:
                evidence["FailedLogins"] = 1

            if "EMAIL_ATTACHMENT_EXECUTED" in log:
                evidence["SuspiciousEmail"] = 1

            if "POWERSHELL" in log:
                evidence["PowerShellExec"] = 1

        # --------------------------------
        # BRUTE FORCE PATTERN
        # --------------------------------
        failed_count = sum(
            1 for log in self.logs
            if "LOGIN_FAILED" in log
        )

        if failed_count >= 3:
            evidence["BruteForcePattern"] = 1

        # --------------------------------
        # MALWARE EXECUTION SEQUENCE
        # --------------------------------
        for i in range(len(self.logs) - 1):

            if (
                "EMAIL_ATTACHMENT_EXECUTED" in self.logs[i]
                and "POWERSHELL" in self.logs[i + 1]
            ):
                evidence["MalwareSequence"] = 1
        # --------------------------------
        # DATA EXFILTRATION RISK SCORING
        # --------------------------------
        risk_score = 0

        for log in self.logs:

            if "LARGE_OUTBOUND_TRANSFER" in log:
                risk_score += 40

            if "UNUSUAL_FTP_UPLOAD" in log:
                risk_score += 40

            if "SUSPICIOUS_DATA_TRANSFER" in log:
                risk_score += 30

            if "POWERSHELL" in log:
                risk_score += 20

            if "destination=" in log:
                risk_score += 10

        evidence["ExfiltrationRiskScore"] = risk_score
        # --------------------------------
        # SEVERITY LEVELS
        # --------------------------------
        if risk_score >= 80:

            evidence["DataExfiltrationPattern"] = 1
            evidence["ExfiltrationSeverity"] = "CRITICAL"

        elif risk_score >= 50:

            evidence["DataExfiltrationPattern"] = 1
            evidence["ExfiltrationSeverity"] = "HIGH"

        elif risk_score >= 30:

            evidence["DataExfiltrationPattern"] = 1
            evidence["ExfiltrationSeverity"] = "MEDIUM"

        elif risk_score > 0:

            evidence["DataExfiltrationPattern"] = 0
            evidence["ExfiltrationSeverity"] = "LOW"
        return evidence