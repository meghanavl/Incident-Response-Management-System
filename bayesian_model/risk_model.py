import pandas as pd
import os

from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.inference import VariableElimination
from pgmpy.estimators import MaximumLikelihoodEstimator


class RiskPredictionModel:

    def __init__(self, data_path="data/incidents.csv"):

        self.data_path = data_path


        # MODEL STRUCTURE
        self.model = DiscreteBayesianNetwork([
        # creating a relationship graph of sorts here
            # Brute Force
            ('FailedLogins', 'BruteForceAttack'),
            ('BruteForcePattern', 'BruteForceAttack'),

            # Phishing
            ('SuspiciousEmail', 'PhishingAttack'),

            # Malware
            ('PowerShellExec', 'MalwareExecution'),
            ('MalwareSequence', 'MalwareExecution'),

            # Data Exfiltration
            ('DataExfiltrationPattern', 'DataExfiltration')
        ])

        # LOAD DATA
        if os.path.exists(self.data_path):
            try:
                self.data = pd.read_csv(self.data_path)
            except:
                self.data = pd.DataFrame()
        else:
            self.data = pd.DataFrame()

        # TRAIN MODEL
        if not self.data.empty:
            self.model.fit(
                self.data,
                estimator=MaximumLikelihoodEstimator
            )

        self.inference = VariableElimination(self.model)

    
    # PREDICT BRUTE FORCE
    def predict_bruteforce(self, evidence):

        return self.inference.query(
            variables=['BruteForceAttack'],
            evidence={
                'FailedLogins': evidence.get("FailedLogins", 0),
                'BruteForcePattern': evidence.get("BruteForcePattern", 0)
            }
        )

    
    # PREDICT PHISHING
    def predict_phishing(self, evidence):

        return self.inference.query(
            variables=['PhishingAttack'],
            evidence={
                'SuspiciousEmail': evidence.get("SuspiciousEmail", 0)
            }
        )
    # PREDICT MALWARE
    def predict_malware(self, evidence):

        return self.inference.query(
            variables=['MalwareExecution'],
            evidence={
                'PowerShellExec': evidence.get("PowerShellExec", 0),
                'MalwareSequence': evidence.get("MalwareSequence", 0)
            }
        )

    # PREDICT EXFILTRATION
    def predict_exfiltration(self, evidence):

        return self.inference.query(
            variables=['DataExfiltration'],
            evidence={
                'DataExfiltrationPattern': evidence.get(
                    "DataExfiltrationPattern", 0
                )
            }
        )

    # SAVE INCIDENT
    def save_incident(self, evidence):

        new_row = {

            # Evidence
            "FailedLogins": evidence.get("FailedLogins", 0),
            "SuspiciousEmail": evidence.get("SuspiciousEmail", 0),
            "PowerShellExec": evidence.get("PowerShellExec", 0),
            "BruteForcePattern": evidence.get("BruteForcePattern", 0),
            "MalwareSequence": evidence.get("MalwareSequence", 0),
            "DataExfiltrationPattern": evidence.get(
                "DataExfiltrationPattern", 0
            ),

            # Labels
            "BruteForceAttack": 1 if (
                evidence.get("FailedLogins")
                and evidence.get("BruteForcePattern")
            ) else 0,

            "PhishingAttack": evidence.get(
                "SuspiciousEmail", 0
            ),

            "MalwareExecution": 1 if (
                evidence.get("PowerShellExec")
                or evidence.get("MalwareSequence")
            ) else 0,

            "DataExfiltration": evidence.get(
                "DataExfiltrationPattern", 0
            )
        }

        columns_order = [

            # Evidence
            "FailedLogins",
            "SuspiciousEmail",
            "PowerShellExec",
            "BruteForcePattern",
            "MalwareSequence",
            "DataExfiltrationPattern",

            # Attacks
            "BruteForceAttack",
            "PhishingAttack",
            "MalwareExecution",
            "DataExfiltration"
        ]

        df_new = pd.DataFrame([new_row])[columns_order]

        if os.path.exists(self.data_path):

            try:
                df_old = pd.read_csv(self.data_path)
                df_old = df_old.reindex(columns=columns_order)

                df = pd.concat(
                    [df_old, df_new],
                    ignore_index=True
                )

            except:
                df = df_new

        else:
            df = df_new

        df.to_csv(self.data_path, index=False)

    # HISTORICAL RECOMMENDATIONS
    def recommend_from_history(self, evidence):

        if self.data.empty:
            return ["No historical data available."]

        similar = self.data[
            (self.data["FailedLogins"] ==
             evidence.get("FailedLogins", 0)) &

            (self.data["SuspiciousEmail"] ==
             evidence.get("SuspiciousEmail", 0)) &

            (self.data["PowerShellExec"] ==
             evidence.get("PowerShellExec", 0))
        ]

        if similar.empty:
            return ["No similar past incidents found."]

        recommendations = []

        if similar["BruteForceAttack"].mean() > 0.5:
            recommendations.append(
                "Lock accounts and monitor login activity"
            )

        if similar["PhishingAttack"].mean() > 0.5:
            recommendations.append(
                "Alert users and block phishing sender"
            )

        if similar["MalwareExecution"].mean() > 0.5:
            recommendations.append(
                "Isolate affected machine immediately"
            )

        if (
            "DataExfiltration" in similar.columns
            and similar["DataExfiltration"].mean() > 0.5
        ):
            recommendations.append(
                "Block outbound traffic and investigate data transfer"
            )

        return (
            recommendations
            if recommendations
            else ["No strong historical pattern"]
        )