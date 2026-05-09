class AttackMapper:

    def map_attack_techniques(

        self,

        evidence,

        dataset_name
    ):

        techniques = []

        # =================================================
        # CMU CERT
        # =================================================

        if dataset_name == "CMU_CERT":

            # ---------------------------------------------
            # VALID ACCOUNTS
            # ---------------------------------------------

            if evidence.get(
                "CredentialAbuse",
                0
            ):

                techniques.append({

                    "technique":
                    "T1078",

                    "name":
                    "Valid Accounts",

                    "tactic":
                    "Defense Evasion"
                })

            # ---------------------------------------------
            # LATERAL MOVEMENT
            # ---------------------------------------------

            if evidence.get(
                "LateralMovement",
                0
            ) > 0:

                techniques.append({

                    "technique":
                    "T1021",

                    "name":
                    "Remote Services",

                    "tactic":
                    "Lateral Movement"
                })

            # ---------------------------------------------
            # ACCOUNT DISCOVERY
            # ---------------------------------------------

            if evidence.get(
                "SuspiciousLogons",
                0
            ) > 10:

                techniques.append({

                    "technique":
                    "T1087",

                    "name":
                    "Account Discovery",

                    "tactic":
                    "Discovery"
                })

        # =================================================
        # CIC IDS2017
        # =================================================

        elif dataset_name == "CIC_IDS2017":

            # ---------------------------------------------
            # NETWORK DOS
            # ---------------------------------------------

            if evidence.get(
                "PotentialDoS",
                0
            ) > 0:

                techniques.append({

                    "technique":
                    "T1498",

                    "name":
                    "Network Denial of Service",

                    "tactic":
                    "Impact"
                })

            # ---------------------------------------------
            # COMMAND & CONTROL
            # ---------------------------------------------

            if evidence.get(
                "BotnetActivity",
                0
            ):

                techniques.append({

                    "technique":
                    "T1071",

                    "name":
                    "Application Layer Protocol",

                    "tactic":
                    "Command and Control"
                })

            # ---------------------------------------------
            # EXPLOIT PUBLIC-FACING APP
            # ---------------------------------------------

            if evidence.get(
                "InfiltrationAttempts",
                0
            ):

                techniques.append({

                    "technique":
                    "T1190",

                    "name":
                    "Exploit Public-Facing Application",

                    "tactic":
                    "Initial Access"
                })

        # =================================================
        # PHISHING
        # =================================================

        elif dataset_name == "PHISHING":

            # ---------------------------------------------
            # SPEARPHISHING LINK
            # ---------------------------------------------

            if evidence.get(
                "MaliciousURLs",
                0
            ) > 5:

                techniques.append({

                    "technique":
                    "T1566.002",

                    "name":
                    "Spearphishing Link",

                    "tactic":
                    "Initial Access"
                })

            # ---------------------------------------------
            # INPUT CAPTURE
            # ---------------------------------------------

            if evidence.get(
                "CredentialHarvesting",
                0
            ):

                techniques.append({

                    "technique":
                    "T1056",

                    "name":
                    "Input Capture",

                    "tactic":
                    "Credential Access"
                })

            # ---------------------------------------------
            # MASQUERADING
            # ---------------------------------------------

            if evidence.get(
                "SuspiciousDomains",
                0
            ) > 10:

                techniques.append({

                    "technique":
                    "T1036",

                    "name":
                    "Masquerading",

                    "tactic":
                    "Defense Evasion"
                })

        # =================================================
        # REMOVE DUPLICATES
        # =================================================

        unique = []

        seen = set()

        for t in techniques:

            key = t["technique"]

            if key not in seen:

                unique.append(t)

                seen.add(key)

        return unique