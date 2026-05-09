class CredentialAbuseDetector:
    def detect(self, events):
        repeated_users = {}
        credential_abuse = 0
        for event in events:
            if event.dataset_type != "CMU_CERT":
                continue
            repeated_users[event.user] = (
                repeated_users.get(
                    event.user,
                    0
                ) + 1
            )
            if repeated_users[event.user] > 2:
                credential_abuse = 1
        return {
            "CredentialAbuse":
            credential_abuse
        }