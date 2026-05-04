# file: chatbot/soc_chat_engine.py

from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity


class SOCChatEngine:

    def __init__(self, evidence=None):
        self.evidence = evidence or {}

        self.model = SentenceTransformer('all-MiniLM-L6-v2')

        self.intents = {
            "phishing": [
                "is this a phishing attack?",
                "email looks suspicious",
                "phishing detected?",
                "suspicious attachment"
            ],
            "bruteforce": [
                "multiple login failures",
                "brute force attack?",
                "too many failed logins",
                "login attack"
            ],
            "malware": [
                "powershell suspicious",
                "malware detected?",
                "is system infected?",
                "script execution issue"
            ],
            "impact": [
                "what is the impact?",
                "how severe is this?",
                "risk level?",
                "impact level?"
            ],
            "general": [
                "what is happening?",
                "summarize incident",
                "what do you see?"
            ]
        }

        self.intent_embeddings = {
            key: self.model.encode(sentences)
            for key, sentences in self.intents.items()
        }

    # -------------------------------
    # MAIN CHAT FUNCTION
    # -------------------------------
    def process_query(self, user_input, model=None):

        if not self.evidence or not model:
            return "No data available. Please run simulation."

        user_input = user_input.lower()

        # model-based probabilities
        brute = model.predict_bruteforce(self.evidence)
        phishing = model.predict_phishing(self.evidence)
        malware = model.predict_malware(self.evidence)

        brute_prob = brute.values[1]
        phishing_prob = phishing.values[1]
        malware_prob = malware.values[1]

        # -------------------------------
        # SMART RESPONSE
        # -------------------------------
        if "summary" in user_input or "attack" in user_input:
            return (
                f"Detected Threats:\n"
                f"- Brute Force: {brute_prob:.2f}\n"
                f"- Phishing: {phishing_prob:.2f}\n"
                f"- Malware: {malware_prob:.2f}"
            )

        elif "phishing" in user_input:
            return f"Phishing probability: {phishing_prob:.2f}"

        elif "brute" in user_input or "login" in user_input:
            return f"Brute force probability: {brute_prob:.2f}"

        elif "malware" in user_input or "powershell" in user_input:
            return f"Malware probability: {malware_prob:.2f}"

        elif "impact" in user_input:
            return self._impact_response()

        elif "why" in user_input or "explain" in user_input:
            return self.explain_decision()

        else:
            return "Ask about attacks, impact, or summary."

    # -------------------------------
    # IMPACT RESPONSE
    # -------------------------------
    def _impact_response(self):

        if not self.evidence:
            return "No evidence available."

        if self.evidence.get("PowerShellExec"):
            return "🔴 HIGH impact due to malware execution."
        elif self.evidence.get("SuspiciousEmail"):
            return "🟠 MEDIUM impact due to phishing."
        elif self.evidence.get("FailedLogins"):
            return "🟡 LOW impact due to login anomalies."

        return "🟢 No significant threat."

    # -------------------------------
    # SUMMARY
    # -------------------------------
    def _summary_response(self):

        if not self.evidence:
            return "No incident data available."

        return (
            f"Summary:\n"
            f"- Failed Logins: {self.evidence.get('FailedLogins')}\n"
            f"- Suspicious Email: {self.evidence.get('SuspiciousEmail')}\n"
            f"- PowerShell Exec: {self.evidence.get('PowerShellExec')}"
        )

    # -------------------------------
    # EXPLANATION
    # -------------------------------
    def explain_decision(self):

        if not self.evidence:
            return "No evidence available."

        explanation = []

        if self.evidence.get("FailedLogins"):
            explanation.append("Multiple failed logins → brute force risk.")

        if self.evidence.get("SuspiciousEmail"):
            explanation.append("Suspicious email → phishing risk.")

        if self.evidence.get("PowerShellExec"):
            explanation.append("PowerShell execution → malware risk.")

        if self.evidence.get("BruteForcePattern"):
            explanation.append("Repeated login pattern strengthens brute force.")

        if self.evidence.get("MalwareSequence"):
            explanation.append("Execution sequence suggests malware.")

        return "\n".join(explanation)