class KillChainMapper:

    def map_phases(
        self,
        events,
        evidence,
        dataset_name
    ):

        phases = []

        # =========================================
        # CMU CERT
        # =========================================

        if dataset_name == "CMU_CERT":

            for event in events:

                activity = (
                    event.activity or ""
                ).lower()

                # =================================
                # RECONNAISSANCE
                # =================================

                if "logon" in activity:

                    phases.append(
                        "Reconnaissance"
                    )

                # =================================
                # CREDENTIAL ACCESS
                # =================================

                if (
                    "admin" in activity
                    or evidence.get(
                        "CredentialAbuse",
                        0
                    )
                ):

                    phases.append(
                        "Credential Access"
                    )

                # =================================
                # LATERAL MOVEMENT
                # =================================

                if evidence.get(
                    "LateralMovement",
                    0
                ) > 0:

                    phases.append(
                        "Lateral Movement"
                    )

                # =================================
                # EXFILTRATION
                # =================================

                if (
                    "usb" in activity
                    or "copy" in activity
                    or "download" in activity
                ):

                    phases.append(
                        "Exfiltration"
                    )

        # =========================================
        # CIC IDS2017
        # =========================================

        elif dataset_name == "CIC_IDS2017":

            for event in events:

                label = (
                    event.activity or ""
                ).lower()

                # =================================
                # RECONNAISSANCE
                # =================================

                if "portscan" in label:

                    phases.append(
                        "Reconnaissance"
                    )

                # =================================
                # EXPLOITATION
                # =================================

                if "infiltration" in label:

                    phases.append(
                        "Exploitation"
                    )

                # =================================
                # COMMAND & CONTROL
                # =================================

                if "bot" in label:

                    phases.append(
                        "Command & Control"
                    )

                # =================================
                # IMPACT
                # =================================

                if "dos" in label:

                    phases.append(
                        "Impact"
                    )

                # =================================
                # CREDENTIAL ACCESS
                # =================================

                if (
                    "ssh-patator" in label
                    or "ftp-patator" in label
                    or "brute" in label
                ):

                    phases.append(
                        "Credential Access"
                    )

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
                # DELIVERY
                # =================================

                if label == "bad":

                    phases.append(
                        "Delivery"
                    )

                # =================================
                # CREDENTIAL ACCESS
                # =================================

                if (
                    "login" in url
                    or "verify" in url
                    or "account" in url
                ):

                    phases.append(
                        "Credential Access"
                    )

                # =================================
                # WEAPONIZATION
                # =================================

                if (
                    "paypal" in url
                    or "microsoft" in url
                    or "bank" in url
                    or "skype" in url
                ):

                    phases.append(
                        "Weaponization"
                    )

        # =========================================
        # REMOVE DUPLICATES
        # =========================================

        phases = list(
            dict.fromkeys(phases)
        )

        # =========================================
        # FALLBACK
        # =========================================

        if not phases:

            phases.append(
                "Monitoring"
            )

        return phases