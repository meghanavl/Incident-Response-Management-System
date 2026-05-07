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

Guidelines:

- Be concise but professional
- Respond like a real SOC analyst
- Avoid generic chatbot replies
- Base conclusions ONLY on evidence
- Clearly explain your reasoning
"""

    def process_query(self, user_query):

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