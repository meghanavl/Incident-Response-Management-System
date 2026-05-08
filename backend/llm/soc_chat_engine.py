#chatbot/soc_chat_engine.py
import ollama


class SOCChatEngine:

    def __init__(self, evidence):

        self.evidence = evidence

    def build_context(self):

        return f"""
You are an expert SOC (Security Operations Center)
incident response analyst.

You are analyzing enterprise insider threat
telemetry from the CMU CERT dataset.

Current security evidence:
{self.evidence}

Your responsibilities:

- Identify suspicious attacker behavior
- Infer attack progression
- Detect possible credential abuse
- Detect possible lateral movement
- Explain incident severity
- Provide threat attribution insights
- Map behavior to MITRE ATT&CK tactics
- Recommend response actions

RESPONSE FORMAT RULES:

- Maximum 4 bullet points
- Maximum 2 short sentences per bullet
- NO paragraphs
- NO generic AI explanations
- Prioritize:
    1. Threat summary
    2. Root cause
    3. Severity
    4. Recommended action
- Sound like a SOC analyst writing an escalation note
- Keep responses operational and concise
- Base conclusions ONLY on evidence
- Clearly explain your reasoning

EXAMPLE RESPONSE STYLE:

- Multiple after-hours logins detected.
- Lateral movement observed across enterprise endpoints.
- Credential abuse behavior likely based on repeated authentication anomalies.
- Recommend isolating affected hosts and resetting compromised accounts.
"""

    def process_query(self, user_query):
        # -----------------------------------
        # SIMPLE CONVERSATIONAL HANDLING
        # -----------------------------------

        simple_greetings = [

            "hi",
            "hello",
            "hey",
            "good morning",
            "good evening"
        ]

        if user_query.lower().strip() in simple_greetings:

            return (
                "Hello. I'm your SOC AI analyst assistant. "
                "Ask me about the current incident, "
                "threat activity, ATT&CK techniques, "
                "or response recommendations."
            )

        response = ollama.chat(

            model="phi3:mini",

            messages=[

                {
                    "role": "system",
                    "content": self.build_context()
                },

                {
                    "role": "user",
                    "content": user_query
                }
            ]
        )

        return response["message"]["content"]