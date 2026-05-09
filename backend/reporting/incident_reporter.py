class IncidentReporter:

    def generate_report(

        self,

        results
    ):

        profile = results[
            "dataset_profile"
        ]

        evidence = results[
            "evidence"
        ]

        severity = results[
            "severity"
        ]

        score = results[
            "scores"
        ]

        bayesian = results[
            "bayesian_analysis"
        ]

        timeline = results[
            "timeline"
        ]

        recommendations = results[
            "recommendations"
        ]

        attack_mapping = results[
            "attack_mapping"
        ]

        kill_chain = results[
            "kill_chain"
        ]

        # =================================================
        # REPORT
        # =================================================

        report = f"""
====================================================
AI-ASSISTED SOC INCIDENT RESPONSE REPORT
====================================================

DATASET INFORMATION
----------------------------------------------------

Dataset:
{profile["name"]}

Security Domain:
{profile["domain"]}

Detection Focus:
{profile["detection_focus"]}

Data Type:
{profile["data_type"]}

Source:
{profile["source"]}

====================================================
INCIDENT SEVERITY
====================================================

Severity Level:
{severity}

Threat Score:
{score}

====================================================
BAYESIAN THREAT ANALYSIS
====================================================

Threat Probability:
{bayesian["probability"]}%

Threat Confidence:
{bayesian["label"]}

Reasoning:
"""

        for reason in bayesian["reasoning"]:

            report += f"\n- {reason}"

        # =================================================
        # SECURITY EVIDENCE
        # =================================================

        report += """

====================================================
EXTRACTED SECURITY EVIDENCE
====================================================
"""

        for key, value in evidence.items():

            report += f"\n{key}: {value}"

        # =================================================
        # TIMELINE
        # =================================================

        report += """

====================================================
ATTACK TIMELINE
====================================================
"""

        for step in timeline:

            report += f"\n- {step}"

        # =================================================
        # MITRE ATT&CK
        # =================================================

        report += """

====================================================
MITRE ATT&CK TECHNIQUES
====================================================
"""

        for attack in attack_mapping:

            report += f"""

Technique:
{attack["technique"]}

Name:
{attack["name"]}

Tactic:
{attack["tactic"]}
"""

        # =================================================
        # KILL CHAIN
        # =================================================

        report += """

====================================================
CYBER KILL CHAIN ANALYSIS
====================================================
"""

        for phase in kill_chain:

            report += f"\n- {phase}"

        # =================================================
        # RECOMMENDATIONS
        # =================================================

        report += """

====================================================
RECOMMENDED RESPONSE ACTIONS
====================================================
"""

        for action in recommendations:

            report += f"\n- {action}"

        # =================================================
        # FINAL SUMMARY
        # =================================================

        report += f"""

====================================================
SOC ANALYST SUMMARY
====================================================

This incident was analyzed under the
{profile["domain"]} domain.

The platform identified telemetry patterns
consistent with suspicious cyber activity.

Threat severity was classified as:
{severity}

Bayesian analysis estimated a threat
probability of:
{bayesian["probability"]}%

Relevant MITRE ATT&CK techniques and
Cyber Kill Chain phases were identified
to support incident investigation and
response prioritization.

====================================================
END OF REPORT
====================================================
"""

        return report