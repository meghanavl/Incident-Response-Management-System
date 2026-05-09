class RecommendationEngine:

    def generate(self, evidence):

        recommendations = []

        # -----------------------------------
        # CMU CERT
        # -----------------------------------

        if evidence.get(
            "CredentialAbuse",
            0
        ):

            recommendations.append(
                "Reset compromised enterprise credentials"
            )

        if evidence.get(
            "LateralMovement",
            0
        ) > 5:

            recommendations.append(
                "Isolate affected enterprise endpoints"
            )

        # -----------------------------------
        # CIC IDS
        # -----------------------------------

        if evidence.get(
            "PotentialDoS",
            0
        ) > 10:

            recommendations.append(
                "Enable network traffic filtering and rate limiting"
            )

        if evidence.get(
            "BotnetActivity",
            0
        ):

            recommendations.append(
                "Investigate compromised hosts for botnet communication"
            )

        # -----------------------------------
        # PHISHING
        # -----------------------------------

        if evidence.get(
            "MaliciousURLs",
            0
        ) > 10:

            recommendations.append(
                "Block malicious URLs and domains immediately"
            )

        if evidence.get(
            "CredentialHarvesting",
            0
        ):

            recommendations.append(
                "Force password reset for potentially targeted users"
            )

        if not recommendations:

            recommendations.append(
                "Continue monitoring security telemetry"
            )

        return recommendations