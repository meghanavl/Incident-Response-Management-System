class AuthenticationDetector:

    def detect(self, events):

        suspicious_logons = 0
        after_hours = 0
        for event in events:

            # -----------------------------------
            # ONLY FOR CMU
            # -----------------------------------

            if event.dataset_type != "CMU_CERT":
                continue
            if event.activity.lower() == "logon":

                suspicious_logons += 1
            try:
                hour = int(

                    event.timestamp
                    .split(" ")[1]
                    .split(":")[0]
                )
                if hour < 6 or hour > 20:
                    after_hours += 1
            except:
                pass
        return {

            "SuspiciousLogons":
            suspicious_logons,

            "AfterHoursLogins":
            after_hours
        }