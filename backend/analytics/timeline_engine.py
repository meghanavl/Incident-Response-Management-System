from datetime import datetime

class TimelineEngine:

    def build(self, events, evidence, dataset_name):

        timeline = []
        # =========================================
        # SORT EVENTS CHRONOLOGICALLY
        # =========================================

        sorted_events = sorted(
            events,
            key=lambda e: self._safe_timestamp(
                e.timestamp
            )
        )
        # =========================================
        # CMU CERT
        # =========================================

        if dataset_name == "CMU_CERT":

            accessed_hosts = {}

            for event in sorted_events[:50]:

                timestamp = (
                    event.timestamp
                    or "UNKNOWN_TIME"
                )

                user = (
                    event.user
                    or "UNKNOWN_USER"
                )

                host = (
                    event.host
                    or "UNKNOWN_HOST"
                )

                activity = (
                    event.activity
                    or "UNKNOWN_ACTIVITY"
                )

                # =================================
                # BASE EVENT
                # =================================

                if activity.lower() == "logon":

                    timeline.append(
                        f"[{timestamp}] INFO: {user} logged into {host}"
                    )

                elif activity.lower() == "logoff":

                    timeline.append(
                        f"[{timestamp}] INFO: {user} logged off from {host}"
                    )

                else:

                    timeline.append(
                        f"[{timestamp}] {user} performed '{activity}' on {host}"
                    )

                # =================================
                # HOST TRACKING
                # =================================

                if user not in accessed_hosts:
                    accessed_hosts[user] = set()

                accessed_hosts[user].add(host)

                # =================================
                # OFF HOURS DETECTION
                # =================================

                hour = self._extract_hour(
                    timestamp
                )

                if hour is not None:

                    if hour < 6 or hour > 22:

                        timeline.append(
                            f"[{timestamp}] ALERT: {user} accessed enterprise assets during off-hours"
                        )

                # =================================
                # LATERAL MOVEMENT
                # =================================

                if len(accessed_hosts[user]) >= 3:

                    timeline.append(
                        f"[{timestamp}] HIGH: Potential lateral movement detected for {user} across multiple hosts"
                    )

                # =================================
                # SUSPICIOUS KEYWORDS
                # =================================

                risky_keywords = [
                    "usb",
                    "download",
                    "copy",
                    "admin"
                ]

                if any(
                    keyword in activity.lower()
                    for keyword in risky_keywords
                ):

                    timeline.append(
                        f"[{timestamp}] MEDIUM: Suspicious activity keyword observed ({activity})"
                    )

        # =========================================
        # CIC IDS2017
        # =========================================

        elif dataset_name == "CIC_IDS2017":

            for index, event in enumerate(
                sorted_events[:50]
            ):

                src_ip = (
                    event.src_ip
                    or "UNKNOWN_SRC"
                )

                dst_ip = (
                    event.dst_ip
                    or "UNKNOWN_DST"
                )

                protocol = (
                    event.protocol
                    or "UNKNOWN_PORT"
                )

                label = (
                    event.activity
                     or "UNKNOWN_TRAFFIC"
                )

                timeline.append(
                    f"[FLOW-{index+1:03}] SRC={src_ip} -> DST={dst_ip} PORT={protocol} LABEL={label}"
                )

                if "dos" in label.lower():

                    timeline.append(
                        f"[FLOW-{index+1:03}] CRITICAL: Potential denial-of-service behavior detected"
                    )

                elif "bot" in label.lower():

                    timeline.append(
                        f"[FLOW-{index+1:03}] HIGH: Possible botnet communication identified"
                    )

                elif "infiltration" in label.lower():

                    timeline.append(
                        f"[FLOW-{index+1:03}] HIGH: Potential network infiltration attempt observed"
                    )
                elif "brute" in label.lower():

                    timeline.append(
                        f"[FLOW-{index+1:03}] HIGH: Brute-force attack pattern detected"
                    )

        # =========================================
        # PHISHING
        # =========================================

        elif dataset_name == "PHISHING":

            for index, event in enumerate(
                sorted_events[:50]
            ):

                url = (
                    event.url
                    or "UNKNOWN_URL"
                )

                label = (
                    event.label
                    or "UNKNOWN"
                )
                timeline.append(
                    f"[URL-{index+1:03}] URL analyzed: {url[:90]}"
                )

                if label.lower() == "bad":

                    timeline.append(
                        f"[URL-{index+1:03}] ALERT: Malicious phishing URL identified"
                    )

                    suspicious_keywords = [
                        "login",
                        "verify",
                        "secure",
                        "account",
                        "update"
                    ]

                    if any(
                        keyword in url.lower()
                        for keyword in suspicious_keywords
                    ):

                        timeline.append(
                            f"[URL-{index+1:03}] HIGH: Credential harvesting indicators detected"
                        )
        # =========================================
        # FALLBACK
        # =========================================

        if not timeline:

            timeline.append(
                "No significant activity detected"
            )

        return timeline

    def _extract_hour(self, timestamp):

        if not timestamp:
            return None

        timestamp_formats = [
            "%m/%d/%Y %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%y %H:%M"
        ]

        for fmt in timestamp_formats:
            try:

                parsed = datetime.strptime(
                    timestamp,
                    fmt
                )

                return parsed.hour

            except Exception:
                continue

        return None

    def _safe_timestamp(self, timestamp):

        if not timestamp:
            return datetime.min

        timestamp_formats = [
            "%m/%d/%Y %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%y %H:%M"
        ]
        for fmt in timestamp_formats:

            try:

                return datetime.strptime(
                    timestamp,
                    fmt
                )

            except Exception:
                continue

        return datetime.min