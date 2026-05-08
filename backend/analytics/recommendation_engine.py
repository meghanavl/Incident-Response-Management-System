class RecommendationEngine:

    def generate(self, evidence):

        actions = []

        if evidence["CredentialAbuse"]:

            actions.append(
                "Force password reset for affected users"
            )

        if evidence["LateralMovement"] > 10:

            actions.append(
                "Isolate suspicious endpoints"
            )

        if evidence["AfterHoursLogins"] > 5:

            actions.append(
                "Review after-hours authentication activity"
            )

        if not actions:

            actions.append(
                "Continue monitoring security telemetry"
            )

        return actions