from backend.detections.auth_detector import (
    AuthenticationDetector
)

from backend.detections.credential_abuse_detector import (
    CredentialAbuseDetector
)

from backend.detections.lateral_movement_detector import (
    LateralMovementDetector
)


class CMUEvidenceEngine:

    def extract(self, events):

        auth = (
            AuthenticationDetector()
            .detect(events)
        )

        credential = (
            CredentialAbuseDetector()
            .detect(events)
        )

        movement = (
            LateralMovementDetector()
            .detect(events)
        )

        evidence = {

            **auth,

            **credential,

            **movement
        }

        evidence["Users"] = len(

            set([e.user for e in events])
        )

        evidence["AffectedHosts"] = len(

            set([e.host for e in events])
        )

        return evidence