class TimelineEngine:

    def build(self, evidence):

        timeline = []

        # -----------------------------------
        # CMU CERT
        # -----------------------------------

        if evidence.get(
            "AfterHoursLogins",
            0
        ) > 5:

            timeline.append(
                "After-hours enterprise access detected"
            )

        if evidence.get(
            "CredentialAbuse",
            0
        ):

            timeline.append(
                "Credential abuse indicators observed"
            )

        if evidence.get(
            "LateralMovement",
            0
        ) > 5:

            timeline.append(
                "Potential lateral movement identified"
            )

        # -----------------------------------
        # CIC IDS
        # -----------------------------------

        if evidence.get(
            "PotentialDoS",
            0
        ) > 10:

            timeline.append(
                "Potential denial-of-service activity detected"
            )

        if evidence.get(
            "BotnetActivity",
            0
        ):

            timeline.append(
                "Botnet communication behavior identified"
            )

        if evidence.get(
            "InfiltrationAttempts",
            0
        ):

            timeline.append(
                "Possible network infiltration attempt detected"
            )

        # -----------------------------------
        # PHISHING
        # -----------------------------------

        if evidence.get(
            "MaliciousURLs",
            0
        ) > 10:

            timeline.append(
                "Large phishing URL campaign identified"
            )

        if evidence.get(
            "CredentialHarvesting",
            0
        ):

            timeline.append(
                "Credential harvesting indicators detected"
            )

        if evidence.get(
            "SuspiciousDomains",
            0
        ) > 10:

            timeline.append(
                "Suspicious spoofed domains observed"
            )

        return timeline