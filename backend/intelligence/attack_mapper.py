class AttackMapper:

    def map_attack_techniques(self, evidence):

        techniques = []

        # -----------------------------------
        # VALID ACCOUNTS
        # -----------------------------------

        if evidence["SuspiciousLogons"] > 10:

            techniques.append({

                "technique": "T1078",

                "name": "Valid Accounts",

                "tactic": "Defense Evasion / Persistence"
            })

        # -----------------------------------
        # AFTER-HOURS ACCESS
        # -----------------------------------

        if evidence["AfterHoursLogins"] > 5:

            techniques.append({

                "technique": "T1036",

                "name": "Masquerading",

                "tactic": "Defense Evasion"
            })

        # -----------------------------------
        # CREDENTIAL ABUSE
        # -----------------------------------

        if evidence["CredentialAbuse"]:

            techniques.append({

                "technique": "T1110",

                "name": "Brute Force / Credential Abuse",

                "tactic": "Credential Access"
            })

        # -----------------------------------
        # LATERAL MOVEMENT
        # -----------------------------------

        if evidence["LateralMovement"] > 5:

            techniques.append({

                "technique": "T1021",

                "name": "Remote Services",

                "tactic": "Lateral Movement"
            })

        # -----------------------------------
        # DEFAULT
        # -----------------------------------

        if not techniques:

            techniques.append({

                "technique": "T1087",

                "name": "Account Discovery",

                "tactic": "Discovery"
            })

        return techniques