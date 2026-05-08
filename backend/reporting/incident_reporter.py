from datetime import datetime


class IncidentReporter:

    def generate_report(self, results):

        evidence = results["evidence"]

        report = f"""
AI-Assisted SOC Incident Response Report
Generated: {datetime.now()}

==================================================
INCIDENT SEVERITY
==================================================

Severity Level:
{results["severity"]}

==================================================
THREAT SUMMARY
==================================================

Suspicious Logons:
{evidence["SuspiciousLogons"]}

After-Hours Activity:
{evidence["AfterHoursLogins"]}

Credential Abuse Detected:
{evidence["CredentialAbuse"]}

Lateral Movement Events:
{evidence["LateralMovement"]}

Affected Users:
{evidence["Users"]}

Affected Hosts:
{evidence["AffectedHosts"]}

==================================================
ATTACK TIMELINE
==================================================
"""

        for step in results["timeline"]:

            report += f"- {step}\n"

        report += """
==================================================
MITRE ATT&CK MAPPING
==================================================
"""

        for attack in results["attack_mapping"]:

            report += (
                f"{attack['technique']} | "
                f"{attack['name']} | "
                f"{attack['tactic']}\n"
            )

        report += """
==================================================
RECOMMENDED ACTIONS
==================================================
"""

        for action in results["recommendations"]:

            report += f"- {action}\n"

        return report