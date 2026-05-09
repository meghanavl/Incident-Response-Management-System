class KillChainMapper:

    def map_phases(

        self,

        evidence,

        dataset_name
    ):

        phases = []

        # =================================================
        # CMU CERT
        # =================================================

        if dataset_name == "CMU_CERT":

            if evidence.get(
                "SuspiciousLogons",
                0
            ) > 10:

                phases.append(
                    "Reconnaissance"
                )

            if evidence.get(
                "CredentialAbuse",
                0
            ):

                phases.append(
                    "Credential Access"
                )

            if evidence.get(
                "LateralMovement",
                0
            ) > 0:

                phases.append(
                    "Lateral Movement"
                )

        # =================================================
        # CIC IDS2017
        # =================================================

        elif dataset_name == "CIC_IDS2017":

            if evidence.get(
                "PotentialDoS",
                0
            ) > 0:

                phases.append(
                    "Impact"
                )

            if evidence.get(
                "BotnetActivity",
                0
            ):

                phases.append(
                    "Command & Control"
                )

            if evidence.get(
                "InfiltrationAttempts",
                0
            ):

                phases.append(
                    "Exploitation"
                )

        # =================================================
        # PHISHING
        # =================================================

        elif dataset_name == "PHISHING":

            if evidence.get(
                "MaliciousURLs",
                0
            ) > 5:

                phases.append(
                    "Delivery"
                )

            if evidence.get(
                "CredentialHarvesting",
                0
            ):

                phases.append(
                    "Credential Access"
                )

            if evidence.get(
                "SuspiciousDomains",
                0
            ) > 10:

                phases.append(
                    "Weaponization"
                )

        # =================================================
        # FALLBACK
        # =================================================

        if not phases:

            phases.append(
                "Monitoring"
            )

        return phases