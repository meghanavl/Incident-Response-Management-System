# file: chatbot/soc_chat_engine.py

class SOCChatEngine:
    def __init__(self, evidence):
        self.evidence = evidence

    def process_query(self, user_input: str) -> str:
        query = user_input.lower()

        if "why" in query or "explain" in query:
            return self.explain_decision()

        if "phishing" in query:
            return self._phishing_response()

        if "brute" in query or "login" in query:
            return self._brute_response()

        if "malware" in query or "powershell" in query:
            return self._malware_response()

        if "impact" in query:
            return self._impact()

        return "Ask about attacks, impact, or ask 'why' for explanation."

    # -------------------------------
    # EXPLANATION ENGINE 
    # -------------------------------
    def explain_decision(self):
        reasons = []

        if self.evidence["FailedLogins"]:
            reasons.append("Multiple failed login attempts detected")

        if self.evidence["BruteForcePattern"]:
            reasons.append("Repeated login pattern suggests automated attack")

        if self.evidence["SuspiciousEmail"]:
            reasons.append("Suspicious email attachment executed")

        if self.evidence["PowerShellExec"]:
            reasons.append("PowerShell activity indicates possible malware execution")

        if self.evidence["MalwareSequence"]:
            reasons.append("Sequence of malicious behavior detected")

        if not reasons:
            return "No significant indicators found. System is normal."

        return "Decision Explanation:\n- " + "\n- ".join(reasons)

    # -------------------------------
    # RESPONSES
    # -------------------------------
    def _phishing_response(self):
        if self.evidence["SuspiciousEmail"]:
            return "Phishing attack likely due to suspicious email activity."
        return "No phishing indicators."

    def _brute_response(self):
        if self.evidence["FailedLogins"] and self.evidence["BruteForcePattern"]:
            return "Brute force attack detected."
        return "No strong brute force indicators."

    def _malware_response(self):
        if self.evidence["PowerShellExec"] and self.evidence["MalwareSequence"]:
            return "Malware execution detected."
        return "No strong malware indicators."

    def _impact(self):
        if self.evidence["PowerShellExec"]:
            return "Impact: HIGH"
        elif self.evidence["SuspiciousEmail"]:
            return "Impact: MEDIUM"
        elif self.evidence["FailedLogins"]:
            return "ℹImpact: LOW"
        return "No impact."