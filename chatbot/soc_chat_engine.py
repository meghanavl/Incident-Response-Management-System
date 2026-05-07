import ollama


class SOCChatEngine:

    def __init__(self, evidence):

        self.evidence = evidence

    def build_context(self):

        return f"""
You are a SOC cybersecurity assistant.

Current attack evidence:
{self.evidence}

Analyze the attack professionally.

Explain:
- attack type
- severity
- possible risks
- recommendations
- summary
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