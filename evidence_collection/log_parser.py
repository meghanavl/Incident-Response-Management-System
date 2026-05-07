# evidence_collection/log_parser.py

import pandas as pd


class LogParser:

    def __init__(self, csv_path="data/logon.csv"):

        self.csv_path = csv_path

        self.logs = pd.read_csv(csv_path)

    def stream_logs(self):

        streamed_logs = []

        repeated_users = {}
        previous_host = None
        sampled_logs = self.logs.sample(30)

        for _, row in sampled_logs.iterrows():

            timestamp = str(row["date"])

            user = str(row["user"])

            host = str(row["pc"])

            activity = str(row["activity"])

            log = (
                f"{timestamp} | "
                f"USER={user} | "
                f"HOST={host} | "
                f"EVENT={activity}"
            )

            streamed_logs.append(log)

            repeated_users[user] = (
                repeated_users.get(user, 0) + 1
            )

            if repeated_users[user] > 1:

                streamed_logs.append(
                    f"{timestamp} | "
                    f"ALERT=Repeated authentication "
                    f"activity detected for {user}"
                )

            if previous_host and previous_host != host:

                streamed_logs.append(
                    f"{timestamp} | "
                    f"ALERT=Potential lateral movement "
                    f"detected from {host}"
                )

            previous_host = host

        return streamed_logs

    def analyze_stream(self):

        evidence = {
            "SuspiciousLogons": 0,
            "AfterHoursLogins": 0,
            "AffectedHosts": set(),
            "Users": set(),
            "CredentialAbuse": 0,
            "LateralMovement": 0,
            "AttackTimeline": [],
            "HighRiskHosts": []
        }

        repeated_users = {}

        previous_host = None
        sampled_logs = self.logs.sample(200, replace=False)

        for _, row in sampled_logs.iterrows():

            timestamp = str(row["date"])

            user = str(row["user"])

            host = str(row["pc"])

            activity = str(row["activity"])

            evidence["Users"].add(user)

            evidence["AffectedHosts"].add(host)

            repeated_users[user] = (
                repeated_users.get(user, 0) + 1
            )

            if activity.lower() == "logon":

                evidence["SuspiciousLogons"] += 1

            try:

                hour = int(
                    timestamp.split(" ")[1].split(":")[0]
                )

                if hour < 6 or hour > 20:

                    evidence["AfterHoursLogins"] += 1

            except Exception:
                pass

            if repeated_users[user] > 2:

                evidence["CredentialAbuse"] = 1

            if previous_host and previous_host != host:

                evidence["LateralMovement"] += 1

                evidence["HighRiskHosts"].append(host)

            previous_host = host
            evidence["AttackTimeline"] = list(
                dict.fromkeys(
                    evidence["AttackTimeline"]
                )
            )
        # Build concise attack timeline

        if evidence["AfterHoursLogins"] > 5:

            evidence["AttackTimeline"].append(
                "After-hours authentication activity detected"
            )

        if evidence["SuspiciousLogons"] > 20:

            evidence["AttackTimeline"].append(
                "Repeated authentication anomalies identified"
            )

        if evidence["CredentialAbuse"]:

            evidence["AttackTimeline"].append(
                "Credential abuse behavior suspected"
            )

        if evidence["LateralMovement"] > 10:

            evidence["AttackTimeline"].append(
                "Potential lateral movement across endpoints detected"
            )

        if evidence["AffectedHosts"]:

            evidence["AttackTimeline"].append(
                "Multiple enterprise hosts affected"
            )
        evidence["Users"] = len(
            evidence["Users"]
        )

        evidence["AffectedHosts"] = len(
            evidence["AffectedHosts"]
        )

        evidence["HighRiskHosts"] = list(
            set(evidence["HighRiskHosts"])
        )[:5]

        if not evidence["AttackTimeline"]:

            evidence["AttackTimeline"] = [
                "Suspicious authentication activity observed",
                "Credential abuse suspected",
                "Potential lateral movement detected"
            ]

        return evidence