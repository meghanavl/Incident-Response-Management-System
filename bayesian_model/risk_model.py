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
        # MODEL STRUCTURE
        # -------------------------------
        self.model = DiscreteBayesianNetwork([
            ('FailedLogins', 'BruteForceAttack'),
            ('BruteForcePattern', 'BruteForceAttack'),

            ('SuspiciousEmail', 'PhishingAttack'),

            ('PowerShellExec', 'MalwareExecution'),
            ('MalwareSequence', 'MalwareExecution')
        ])

        # -------------------------------
        # LOAD DATA
        # -------------------------------
        if os.path.exists(self.data_path):
            try:
                self.data = pd.read_csv(self.data_path)
            except:
                self.data = pd.DataFrame()
        else:
            self.data = pd.DataFrame()

        # -------------------------------
        # TRAIN MODEL (only if data exists)
        # -------------------------------
        if not self.data.empty:
            self.model.fit(self.data, estimator=MaximumLikelihoodEstimator)

        self.inference = VariableElimination(self.model)

    # -------------------------------
    # PREDICTIONS
    # -------------------------------
    def predict_bruteforce(self, evidence):
        return self.inference.query(
            variables=['BruteForceAttack'],
            evidence={
                'FailedLogins': evidence.get("FailedLogins", 0),
                'BruteForcePattern': evidence.get("BruteForcePattern", 0)
            }
        )

    def predict_phishing(self, evidence):
        return self.inference.query(
            variables=['PhishingAttack'],
            evidence={
                'SuspiciousEmail': evidence.get("SuspiciousEmail", 0)
            }
        )

    def predict_malware(self, evidence):
        return self.inference.query(
            variables=['MalwareExecution'],
            evidence={
                'PowerShellExec': evidence.get("PowerShellExec", 0),
                'MalwareSequence': evidence.get("MalwareSequence", 0)
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

            # Correct labels
            "BruteForceAttack": 1 if (
                evidence.get("FailedLogins") and evidence.get("BruteForcePattern")
            ) else 0,

            "PhishingAttack": evidence.get("SuspiciousEmail", 0),

            "MalwareExecution": 1 if (
                evidence.get("PowerShellExec") or evidence.get("MalwareSequence")
            ) else 0,
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
            try:
                df_old = pd.read_csv(self.data_path)
                df_old = df_old.reindex(columns=columns_order)
                df = pd.concat([df_old, df_new], ignore_index=True)
            except:
                df = df_new
        else:
            df = df_new

        df.to_csv(self.data_path, index=False)

    # -------------------------------
    # HISTORICAL RECOMMENDATION
    # -------------------------------
    def recommend_from_history(self, evidence):

        if self.data.empty:
            return ["No historical data available."]

        similar = self.data[
            (self.data["FailedLogins"] == evidence.get("FailedLogins", 0)) &
            (self.data["SuspiciousEmail"] == evidence.get("SuspiciousEmail", 0)) &
            (self.data["PowerShellExec"] == evidence.get("PowerShellExec", 0))
        ]

        if similar.empty:
            return ["No similar past incidents found."]

        recommendations = []

        if similar["BruteForceAttack"].mean() > 0.5:
            recommendations.append("Lock accounts (based on past incidents)")

        if similar["PhishingAttack"].mean() > 0.5:
            recommendations.append("Alert users about phishing emails")

        if similar["MalwareExecution"].mean() > 0.5:
            recommendations.append("Isolate affected machine")

        return recommendations if recommendations else ["No strong historical pattern"]