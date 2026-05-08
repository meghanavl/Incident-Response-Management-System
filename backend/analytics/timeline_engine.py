class TimelineEngine:

    def build(self, evidence):

        timeline = []

        if evidence["AfterHoursLogins"] > 5:

            timeline.append(
                "After-hours authentication activity detected"
            )

        if evidence["SuspiciousLogons"] > 20:

            timeline.append(
                "Repeated authentication anomalies identified"
            )

        if evidence["CredentialAbuse"]:

            timeline.append(
                "Credential abuse behavior suspected"
            )

        if evidence["LateralMovement"] > 10:

            timeline.append(
                "Potential lateral movement across endpoints detected"
            )

        if not timeline:

            timeline = [
                "Suspicious authentication activity observed"
            ]

        return timeline