from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination


class RiskPredictionModel:

    def __init__(self):

        # Define relationships
        self.model = DiscreteBayesianNetwork([
            ('FailedLogins', 'BruteForceAttack'),
            ('SuspiciousEmail', 'PhishingAttack'),
            ('PowerShellExec', 'MalwareExecution')
        ])

        self._build_probabilities()

    def _build_probabilities(self):

        # Evidence probabilities
        cpd_failed_logins = TabularCPD(
            variable='FailedLogins',
            variable_card=2,
            values=[[0.7], [0.3]]
        )

        cpd_email = TabularCPD(
            variable='SuspiciousEmail',
            variable_card=2,
            values=[[0.8], [0.2]]
        )

        cpd_powershell = TabularCPD(
            variable='PowerShellExec',
            variable_card=2,
            values=[[0.85], [0.15]]
        )

        # Attack probabilities
        cpd_bruteforce = TabularCPD(
            variable='BruteForceAttack',
            variable_card=2,
            values=[[0.9, 0.2],
                    [0.1, 0.8]],
            evidence=['FailedLogins'],
            evidence_card=[2]
        )

        cpd_phishing = TabularCPD(
            variable='PhishingAttack',
            variable_card=2,
            values=[[0.85, 0.3],
                    [0.15, 0.7]],
            evidence=['SuspiciousEmail'],
            evidence_card=[2]
        )

        cpd_malware = TabularCPD(
            variable='MalwareExecution',
            variable_card=2,
            values=[[0.9, 0.25],
                    [0.1, 0.75]],
            evidence=['PowerShellExec'],
            evidence_card=[2]
        )

        self.model.add_cpds(
            cpd_failed_logins,
            cpd_email,
            cpd_powershell,
            cpd_bruteforce,
            cpd_phishing,
            cpd_malware
        )

        self.model.check_model()

        self.inference = VariableElimination(self.model)

    def predict_bruteforce(self, failed_logins):

        result = self.inference.query(
            variables=['BruteForceAttack'],
            evidence={'FailedLogins': failed_logins}
        )

        return result


if __name__ == "__main__":

    model = RiskPredictionModel()

    result = model.predict_bruteforce(failed_logins=1)

    print("\nBrute Force Attack Probability:")
    print(result)