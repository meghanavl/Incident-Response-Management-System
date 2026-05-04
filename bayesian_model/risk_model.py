# file: bayesian_model/risk_model.py

import pandas as pd
import os

from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.inference import VariableElimination
from pgmpy.estimators import MaximumLikelihoodEstimator


class RiskPredictionModel:

    def __init__(self, data_path="data/incidents.csv"):

        self.data_path = data_path

        # -------------------------------
        # FULL RELATIONSHIP MODEL
        # -------------------------------
        self.model = DiscreteBayesianNetwork([
            ('FailedLogins', 'BruteForceAttack'),
            ('BruteForcePattern', 'BruteForceAttack'),

            ('SuspiciousEmail', 'PhishingAttack'),

            ('PowerShellExec', 'MalwareExecution'),
            ('MalwareSequence', 'MalwareExecution')  # NEW
        ])

        # -------------------------------
        # LOAD DATA
        # -------------------------------
        if os.path.exists(self.data_path):
            self.data = pd.read_csv(self.data_path)
        else:
            self.data = pd.DataFrame()

        # -------------------------------
        # TRAIN MODEL
        # -------------------------------
        if not self.data.empty:
            self.model.fit(self.data, estimator=MaximumLikelihoodEstimator)

        self.inference = VariableElimination(self.model)

    # -------------------------------
    # PREDICT BRUTE FORCE
    # -------------------------------
    def predict_bruteforce(self, evidence):

        return self.inference.query(
            variables=['BruteForceAttack'],
            evidence={
                'FailedLogins': evidence["FailedLogins"],
                'BruteForcePattern': evidence["BruteForcePattern"]
            }
        )

    # -------------------------------
    # PREDICT PHISHING
    # -------------------------------
    def predict_phishing(self, evidence):

        return self.inference.query(
            variables=['PhishingAttack'],
            evidence={
                'SuspiciousEmail': evidence["SuspiciousEmail"]
            }
        )

    # -------------------------------
    # PREDICT MALWARE
    # -------------------------------
    def predict_malware(self, evidence):

        return self.inference.query(
            variables=['MalwareExecution'],
            evidence={
                'PowerShellExec': evidence["PowerShellExec"],
                'MalwareSequence': evidence["MalwareSequence"]
            }
        )

    # -------------------------------
    # SAVE INCIDENT (LEARNING)
    # -------------------------------
    def save_incident(self, evidence):

        new_row = {
            "FailedLogins": evidence.get("FailedLogins", 0),
            "SuspiciousEmail": evidence.get("SuspiciousEmail", 0),
            "PowerShellExec": evidence.get("PowerShellExec", 0),
            "BruteForcePattern": evidence.get("BruteForcePattern", 0),
            "MalwareSequence": evidence.get("MalwareSequence", 0),

            "BruteForceAttack": evidence.get("BruteForcePattern", 0),
            "PhishingAttack": evidence.get("SuspiciousEmail", 0),
            "MalwareExecution": evidence.get("MalwareSequence", 0),
        }

        columns_order = [
            "FailedLogins",
            "SuspiciousEmail",
            "PowerShellExec",
            "BruteForcePattern",
            "MalwareSequence",
            "BruteForceAttack",
            "PhishingAttack",
            "MalwareExecution"
        ]

        df_new = pd.DataFrame([new_row])[columns_order]

        if os.path.exists(self.data_path):
            df_old = pd.read_csv(self.data_path)
            df_old = df_old.reindex(columns=columns_order)
            df = pd.concat([df_old, df_new], ignore_index=True)
        else:
            df = df_new

        df.to_csv(self.data_path, index=False)