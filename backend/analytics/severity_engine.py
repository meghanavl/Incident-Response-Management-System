class SeverityEngine:

    def calculate(

        self,

        evidence,

        bayesian_analysis
    ):

        score = 0

        severity_reasons = []

        # =================================================
        # CMU CERT
        # =================================================

        suspicious_logons = evidence.get(
            "SuspiciousLogons",
            0
        )

        if suspicious_logons > 10:

            score += 25

            severity_reasons.append(
                "High authentication anomaly volume"
            )

        after_hours = evidence.get(
            "AfterHoursLogins",
            0
        )

        if after_hours > 5:

            score += 20

            severity_reasons.append(
                "After-hours access behavior"
            )

        lateral = evidence.get(
            "LateralMovement",
            0
        )

        if lateral > 5:

            score += 35

            severity_reasons.append(
                "Potential lateral movement detected"
            )

        if evidence.get(
            "CredentialAbuse",
            0
        ):

            score += 40

            severity_reasons.append(
                "Credential abuse indicators identified"
            )

        # =================================================
        # CIC IDS2017
        # =================================================

        dos = evidence.get(
            "PotentialDoS",
            0
        )

        if dos > 10:

            score += 40

            severity_reasons.append(
                "Potential denial-of-service activity"
            )

        if evidence.get(
            "BotnetActivity",
            0
        ):

            score += 35

            severity_reasons.append(
                "Botnet communication behavior"
            )

        if evidence.get(
            "InfiltrationAttempts",
            0
        ):

            score += 35

            severity_reasons.append(
                "Network infiltration indicators"
            )

        suspicious_flows = evidence.get(
            "SuspiciousFlows",
            0
        )

        if suspicious_flows > 20:

            score += 20

            severity_reasons.append(
                "Large volume suspicious traffic flows"
            )

        # =================================================
        # PHISHING
        # =================================================

        malicious_urls = evidence.get(
            "MaliciousURLs",
            0
        )

        if malicious_urls > 20:

            score += 35

            severity_reasons.append(
                "Large phishing campaign volume"
            )

        if evidence.get(
            "CredentialHarvesting",
            0
        ):

            score += 40

            severity_reasons.append(
                "Credential harvesting behavior"
            )

        suspicious_domains = evidence.get(
            "SuspiciousDomains",
            0
        )

        if suspicious_domains > 10:

            score += 25

            severity_reasons.append(
                "Suspicious spoofed domains"
            )

        # =================================================
        # BAYESIAN BOOST
        # =================================================

        probability = bayesian_analysis[
            "probability"
        ]

        score += int(probability * 0.5)

        # =================================================
        # SEVERITY LABELS
        # =================================================

        if score < 40:

            severity = "LOW"

        elif score < 80:

            severity = "MEDIUM"

        elif score < 140:

            severity = "HIGH"

        else:

            severity = "CRITICAL"

        return {

            "severity": severity,

            "scores": score,

            "reasons": severity_reasons
        }