from collections import defaultdict
from datetime import datetime


class UEBAEngine:

    def analyze(self, events):

        user_profiles = defaultdict(
            lambda: {
                "hosts": set(),
                "activities": defaultdict(int),
                "hours": [],
                "total_events": 0,
                "risk_score": 0,
                "anomalies": []
            }
        )

        suspicious_users = []

        for event in events:

            if event.dataset_type != "CMU_CERT":
                continue

            user = event.user or "UNKNOWN_USER"
            host = event.host or "UNKNOWN_HOST"
            activity = (
                event.activity or "UNKNOWN_ACTIVITY"
            )

            profile = user_profiles[user]

            profile["hosts"].add(host)
            profile["activities"][activity] += 1
            profile["total_events"] += 1

            hour = self._extract_hour(
                event.timestamp
            )

            if hour is not None:
                profile["hours"].append(hour)

                # ====================================
                # OFF-HOURS ACCESS
                # ====================================

                if hour < 6 or hour > 22:

                    if "off_hours" not in profile:

                        profile["off_hours"] = True

                        profile["risk_score"] += 15

                        profile["anomalies"].append(
                            "Repeated off-hours access behavior"
                        )

            # ====================================
            # HIGH-RISK KEYWORDS
            # ====================================

            risky_keywords = [
                "logon",
                "connect",
                "usb",
                "file copy",
                "download",
                "admin"
            ]

            if any(
                keyword in activity.lower()
                for keyword in risky_keywords
            ):

                profile["risk_score"] += 10

        # ========================================
        # BASELINE DEVIATION ANALYSIS
        # ========================================

        for user, profile in user_profiles.items():

            unique_hosts = len(
                profile["hosts"]
            )

            total_events = profile[
                "total_events"
            ]

            # ====================================
            # HOST SPREAD
            # ====================================

            if unique_hosts >= 2:

                profile["risk_score"] += 25

                profile["anomalies"].append(
                    f"Accessed unusually high number of hosts ({unique_hosts})"
                )

            # ====================================
            # ACTIVITY SPIKE
            # ====================================

            if total_events >= 5:

                profile["risk_score"] += 20

                profile["anomalies"].append(
                    f"High activity spike detected ({total_events} events)"
                )

            # ====================================
            # LATERAL MOVEMENT HEURISTIC
            # ====================================

            logon_events = sum(
                count
                for activity, count in profile[
                    "activities"
                ].items()
                if "logon" in activity.lower()
            )

            if logon_events >= 3 and unique_hosts >= 2:

                profile["risk_score"] += 30

                profile["anomalies"].append(
                    "Potential lateral movement behavior"
                )

            # ====================================
            # FINAL RISK NORMALIZATION
            # ====================================

            profile["risk_score"] = min(
                profile["risk_score"],
                100
            )

            if profile["risk_score"] >= 45:

                suspicious_users.append({
                    "user": user,
                    "risk_score": profile[
                        "risk_score"
                    ],
                    "hosts": unique_hosts,
                    "events": total_events,
                    "anomalies": profile[
                        "anomalies"
                    ]
                })

        suspicious_users = sorted(
            suspicious_users,
            key=lambda x: x["risk_score"],
            reverse=True
        )

        overall_risk = 0

        if suspicious_users:

            overall_risk = int(
                sum(
                    user["risk_score"]
                    for user in suspicious_users
                ) / len(suspicious_users)
            )

        return {
            "ueba_risk_score": overall_risk,
            "suspicious_users": suspicious_users,
            "user_profiles": user_profiles
        }

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