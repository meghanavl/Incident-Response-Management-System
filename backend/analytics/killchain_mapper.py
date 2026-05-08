class KillChainMapper:

    def map_phases(self, evidence):

        phases = []

        if evidence["AfterHoursLogins"] > 5:

            phases.append("Reconnaissance")

        if evidence["SuspiciousLogons"] > 10:

            phases.append("Exploitation")

        if evidence["CredentialAbuse"]:

            phases.append("Installation")

        if evidence["LateralMovement"] > 10:

            phases.append("Command & Control")

        if not phases:

            phases.append(
                "No advanced attack stages detected"
            )

        return phases