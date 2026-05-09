class BayesianEngine:

    def calculate_threat_probability(

        self,

        evidence
    ):

        probability = 10

        reasoning = []

        # =================================================
        # CMU CERT
        # =================================================

        if evidence.get(
            "SuspiciousLogons",
            0
        ) > 10:

            probability += 20

            reasoning.append(
                "Authentication anomalies increased threat likelihood"
            )

        if evidence.get(
            "CredentialAbuse",
            0
        ):

            probability += 30

            reasoning.append(
                "Credential abuse strongly correlates with insider threats"
            )

        if evidence.get(
            "LateralMovement",
            0
        ) > 5:

            probability += 25

            reasoning.append(
                "Lateral movement behavior observed"
            )

        # =================================================
        # CIC IDS
        # =================================================

        if evidence.get(
            "PotentialDoS",
            0
        ) > 10:

            probability += 30

            reasoning.append(
                "DoS traffic indicators identified"
            )

        if evidence.get(
            "BotnetActivity",
            0
        ):

            probability += 25

            reasoning.append(
                "Botnet communication patterns observed"
            )

        if evidence.get(
            "InfiltrationAttempts",
            0
        ):

            probability += 20

            reasoning.append(
                "Potential network intrusion behavior"
            )

        # =================================================
        # PHISHING
        # =================================================

        if evidence.get(
            "MaliciousURLs",
            0
        ) > 20:

            probability += 30

            reasoning.append(
                "Large volume malicious URLs detected"
            )

        if evidence.get(
            "CredentialHarvesting",
            0
        ):

            probability += 25

            reasoning.append(
                "Credential harvesting indicators observed"
            )

        if evidence.get(
            "SuspiciousDomains",
            0
        ) > 10:

            probability += 15

            reasoning.append(
                "Suspicious phishing domains identified"
            )

        # =================================================
        # LIMIT
        # =================================================

        probability = min(
            probability,
            99
        )

        # =================================================
        # CONFIDENCE LABEL
        # =================================================

        if probability < 40:

            label = "LOW CONFIDENCE THREAT"

        elif probability < 70:

            label = "MODERATE CONFIDENCE THREAT"

        else:

            label = "HIGH CONFIDENCE THREAT"

        return {

            "probability": probability,

            "label": label,

            "reasoning": reasoning
        }