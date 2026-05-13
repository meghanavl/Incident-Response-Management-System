class AttackMapper:

    def map_attack_techniques(
        self,
        events,
        evidence,
        dataset_name
    ):

        techniques = []

        # =========================================
        # CMU CERT
        # =========================================

        if dataset_name == "CMU_CERT":

            user_hosts = {}

            for event in events:

                activity = (
                    event.activity or ""
                ).lower()

                user = (
                    event.user or "UNKNOWN"
                )

                host = (
                    event.host or "UNKNOWN"
                )

                # =================================
                # VALID ACCOUNTS
                # =================================

                if (
                    "admin" in activity
                    or evidence.get(
                        "CredentialAbuse",
                        0
                    )
                ):

                    techniques.append({

                        "technique":
                        "T1078",

                        "name":
                        "Valid Accounts",

                        "tactic":
                        "Defense Evasion"
                    })

                # =================================
                # EXFILTRATION
                # =================================

                if (
                    "usb" in activity
                    or "copy" in activity
                    or "download" in activity
                ):

                    techniques.append({

                        "technique":
                        "T1052",

                        "name":
                        "Exfiltration Over Physical Medium",

                        "tactic":
                        "Exfiltration"
                    })

                # =================================
                # ACCOUNT DISCOVERY
                # =================================

                if "logon" in activity:

                    techniques.append({

                        "technique":
                        "T1087",

                        "name":
                        "Account Discovery",

                        "tactic":
                        "Discovery"
                    })

                # =================================
                # HOST TRACKING
                # =================================

                if user not in user_hosts:

                    user_hosts[user] = set()

                user_hosts[user].add(host)

            # =====================================
            # LATERAL MOVEMENT
            # =====================================

            for user, hosts in user_hosts.items():

                if len(hosts) >= 3:

                    techniques.append({

                        "technique":
                        "T1021",

                        "name":
                        "Remote Services",

                        "tactic":
                        "Lateral Movement"
                    })

        # =========================================
        # CIC IDS2017
        # =========================================

        elif dataset_name == "CIC_IDS2017":

            for event in events:

                label = (
                    event.activity or ""
                ).lower()

                # =================================
                # DOS
                # =================================

                if "dos" in label:

                    techniques.append({

                        "technique":
                        "T1498",

                        "name":
                        "Network Denial of Service",

                        "tactic":
                        "Impact"
                    })

                # =================================
                # BOTNET
                # =================================

                if "bot" in label:

                    techniques.append({

                        "technique":
                        "T1071",

                        "name":
                        "Application Layer Protocol",

                        "tactic":
                        "Command and Control"
                    })

                # =================================
                # INFILTRATION
                # =================================

                if "infiltration" in label:

                    techniques.append({

                        "technique":
                        "T1190",

                        "name":
                        "Exploit Public-Facing Application",

                        "tactic":
                        "Initial Access"
                    })

                # =================================
                # BRUTE FORCE
                # =================================

                if (
                    "ssh-patator" in label
                    or "ftp-patator" in label
                    or "brute" in label
                ):

                    techniques.append({

                        "technique":
                        "T1110",

                        "name":
                        "Brute Force",

                        "tactic":
                        "Credential Access"
                    })

                # =================================
                # PORT SCANNING
                # =================================

                if "portscan" in label:

                    techniques.append({

                        "technique":
                        "T1046",

                        "name":
                        "Network Service Discovery",

                        "tactic":
                        "Discovery"
                    })

        # =========================================
        # PHISHING
        # =========================================

        elif dataset_name == "PHISHING":

            for event in events:

                url = (
                    event.url or ""
                ).lower()

                label = (
                    event.label or ""
                ).lower()

                # =================================
                # SPEARPHISHING
                # =================================

                if label == "bad":

                    techniques.append({

                        "technique":
                        "T1566.002",

                        "name":
                        "Spearphishing Link",

                        "tactic":
                        "Initial Access"
                    })

                # =================================
                # CREDENTIAL HARVESTING
                # =================================

                suspicious_keywords = [
                    "login",
                    "verify",
                    "secure",
                    "account",
                    "update"
                ]

                if any(
                    keyword in url
                    for keyword in suspicious_keywords
                ):

                    techniques.append({

                        "technique":
                        "T1056",

                        "name":
                        "Input Capture",

                        "tactic":
                        "Credential Access"
                    })

                # =================================
                # MASQUERADING
                # =================================

                spoof_keywords = [
                    "paypal",
                    "microsoft",
                    "skype",
                    "bank"
                ]

                if any(
                    keyword in url
                    for keyword in spoof_keywords
                ):

                    techniques.append({

                        "technique":
                        "T1036",

                        "name":
                        "Masquerading",

                        "tactic":
                        "Defense Evasion"
                    })

        # =========================================
        # REMOVE DUPLICATES
        # =========================================

        unique = []

        seen = set()

        for technique in techniques:

            key = technique["technique"]

            if key not in seen:

                unique.append(
                    technique
                )

                seen.add(key)

        return unique