# file: bayesian_model/risk_model.py

import os
import pandas as pd

from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.inference import VariableElimination
from pgmpy.estimators import MaximumLikelihoodEstimator


class RiskPredictionModel:

    def __init__(self, data_path="data/incidents.csv"):

        self.data_path = data_path

        # ------------------------------------------------
        # BAYESIAN RELATIONSHIPS
        # ------------------------------------------------
        self.model = DiscreteBayesianNetwork([

            ("FailedLogins", "BruteForceAttack"),
            ("BruteForcePattern", "BruteForceAttack"),

            ("SuspiciousEmail", "PhishingAttack"),

            ("PowerShellExec", "MalwareExecution"),
            ("MalwareSequence", "MalwareExecution"),

            ("DataExfiltrationPattern", "DataExfiltration")
        ])

        # ------------------------------------------------
        # LOAD DATASET
        # ------------------------------------------------
        if os.path.exists(self.data_path):

            self.data = pd.read_csv(self.data_path)

        else:

            self.data = pd.DataFrame(columns=[

                "FailedLogins",
                "SuspiciousEmail",
                "PowerShellExec",
                "BruteForcePattern",
                "MalwareSequence",
                "DataExfiltrationPattern",

                "BruteForceAttack",
                "PhishingAttack",
                "MalwareExecution",
                "DataExfiltration"
            ])

        # ------------------------------------------------
        # TRAIN MODEL
        # ------------------------------------------------
        if not self.data.empty:

            self.model.fit(
                self.data,
                estimator=MaximumLikelihoodEstimator
            )

        self.inference = VariableElimination(
            self.model
        )

    # ------------------------------------------------
    # BRUTE FORCE
    # ------------------------------------------------
    def predict_bruteforce(self, evidence):

        return self.inference.query(

            variables=["BruteForceAttack"],

            evidence={
                "FailedLogins":
                    evidence["FailedLogins"],

                "BruteForcePattern":
                    evidence["BruteForcePattern"]
            }
        )

    # ------------------------------------------------
    # PHISHING
    # ------------------------------------------------
    def predict_phishing(self, evidence):

        return self.inference.query(

            variables=["PhishingAttack"],

            evidence={
                "SuspiciousEmail":
                    evidence["SuspiciousEmail"]
            }
        )

    # ------------------------------------------------
    # MALWARE
    # ------------------------------------------------
    def predict_malware(self, evidence):

        return self.inference.query(

            variables=["MalwareExecution"],

            evidence={

                "PowerShellExec":
                    evidence["PowerShellExec"],

                "MalwareSequence":
                    evidence["MalwareSequence"]
            }
        )

    # ------------------------------------------------
    # DATA EXFILTRATION
    # ------------------------------------------------
    def predict_exfiltration(self, evidence):

        return self.inference.query(

            variables=["DataExfiltration"],

            evidence={

                "DataExfiltrationPattern":
                    evidence["DataExfiltrationPattern"]
            }
        )

    # ------------------------------------------------
    # SAVE INCIDENT
    # ------------------------------------------------
    def save_incident(self, evidence):

        new_row = {

            "FailedLogins":
                evidence.get("FailedLogins", 0),

            "SuspiciousEmail":
                evidence.get("SuspiciousEmail", 0),

            "PowerShellExec":
                evidence.get("PowerShellExec", 0),

            "BruteForcePattern":
                evidence.get("BruteForcePattern", 0),

            "MalwareSequence":
                evidence.get("MalwareSequence", 0),

            "DataExfiltrationPattern":
                evidence.get("DataExfiltrationPattern", 0),

            # ---------------- ATTACK LABELS ----------------

            "BruteForceAttack": 1 if (

                evidence.get("FailedLogins")
                and evidence.get("BruteForcePattern")

            ) else 0,

            "PhishingAttack":
                evidence.get("SuspiciousEmail", 0),

            "MalwareExecution": 1 if (

                evidence.get("PowerShellExec")
                or evidence.get("MalwareSequence")

            ) else 0,

            "DataExfiltration":
                evidence.get(
                    "DataExfiltrationPattern",
                    0
                )
        }

        columns_order = [

            "FailedLogins",
            "SuspiciousEmail",
            "PowerShellExec",
            "BruteForcePattern",
            "MalwareSequence",
            "DataExfiltrationPattern",

            "BruteForceAttack",
            "PhishingAttack",
            "MalwareExecution",
            "DataExfiltration"
        ]

        df_new = pd.DataFrame(
            [new_row]
        )[columns_order]

        if os.path.exists(self.data_path):

            df_old = pd.read_csv(
                self.data_path
            )

            df_old = df_old.reindex(
                columns=columns_order
            )

            df = pd.concat(
                [df_old, df_new],
                ignore_index=True
            )

        else:

            df = df_new

        df.to_csv(
            self.data_path,
            index=False
        )

    # ------------------------------------------------
    # RECOMMENDATIONS
    # ------------------------------------------------
    def recommend_from_history(self, evidence):

        recommendations = []

        if evidence.get("BruteForcePattern"):

            recommendations.append(
                "Lock affected accounts immediately."
            )

            recommendations.append(
                "Enable MFA for authentication."
            )

        if evidence.get("SuspiciousEmail"):

            recommendations.append(
                "Quarantine suspicious email attachments."
            )

            recommendations.append(
                "Conduct phishing awareness checks."
            )

        if evidence.get("PowerShellExec"):

            recommendations.append(
                "Isolate infected endpoints."
            )

            recommendations.append(
                "Terminate suspicious PowerShell sessions."
            )

        if evidence.get("DataExfiltrationPattern"):

            recommendations.append(
                "Block outbound traffic immediately."
            )

            recommendations.append(
                "Investigate possible data theft."
            )

        if not recommendations:

            recommendations.append(
                "Continue monitoring system activity."
            )

        return recommendations