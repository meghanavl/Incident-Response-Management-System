class SeverityEngine:

    def calculate(self, evidence):

        # -----------------------------------
        # WEIGHTED RISK FACTORS
        # -----------------------------------

        suspicious_score = min(

            evidence["SuspiciousLogons"] * 0.5,

            25
        )

        after_hours_score = min(

            evidence["AfterHoursLogins"] * 2,

            20
        )

        lateral_score = min(

            evidence["LateralMovement"] * 4,

            35
        )

        credential_score = (

            30
            if evidence["CredentialAbuse"]
            else 0
        )

        # -----------------------------------
        # TOTAL SCORE
        # -----------------------------------

        overall_score = (

            suspicious_score +

            after_hours_score +

            lateral_score +

            credential_score
        )

        # -----------------------------------
        # SEVERITY LEVELS
        # -----------------------------------

        if overall_score >= 75:

            severity = "CRITICAL"

        elif overall_score >= 50:

            severity = "HIGH"

        elif overall_score >= 25:

            severity = "MEDIUM"

        else:

            severity = "LOW"

        return {

            "severity": severity,

            "scores": {

                "Abnormal Authentication":

                round(suspicious_score, 1),

                "After-Hours Activity":

                round(after_hours_score, 1),

                "Lateral Movement":

                round(lateral_score, 1),

                "Credential Abuse":

                credential_score
            }
        }