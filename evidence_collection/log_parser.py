import random


class LogParser:

    def __init__(self):
        self.logs = []

    def generate_sample_logs(self):

        possible_logs = [
            "LOGIN_FAILED user=admin ip=192.168.1.20",
            "LOGIN_FAILED user=root ip=10.0.0.5",
            "EMAIL_ATTACHMENT_EXECUTED file=invoice.exe",
            "POWERSHELL suspicious_script.ps1",
            "NORMAL_LOGIN user=john",
            "FILE_DOWNLOAD report.pdf",
        ]

        # simulate log generation
        for _ in range(10):
            log = random.choice(possible_logs)
            self.logs.append(log)

        return self.logs

    def analyze_logs(self):

        evidence = {
            "FailedLogins": 0,
            "SuspiciousEmail": 0,
            "PowerShellExec": 0
        }

        for log in self.logs:

            if "LOGIN_FAILED" in log:
                evidence["FailedLogins"] = 1

            if "EMAIL_ATTACHMENT_EXECUTED" in log:
                evidence["SuspiciousEmail"] = 1

            if "POWERSHELL" in log:
                evidence["PowerShellExec"] = 1

        return evidence


if __name__ == "__main__":

    parser = LogParser()

    logs = parser.generate_sample_logs()

    print("\nGenerated Logs:")
    for log in logs:
        print(log)

    evidence = parser.analyze_logs()

    print("\nDetected Evidence:")
    print(evidence)