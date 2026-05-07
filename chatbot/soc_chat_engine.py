import ollama


class SOCChatEngine:

    def __init__(self, evidence):

        self.evidence = evidence

    def build_context(self):

        return f"""
You are a SOC cybersecurity assistant.

Current security evidence:
{self.evidence}

Rules:
- Give concise responses
- Keep answers concise and under 80 words unless the user asks for details.
- Be clear and professional
- Focus only on cybersecurity analysis
- Avoid unnecessary explanations
- Use bullet points when useful
- Format responses using short bullet points.

You can:
- summarize incidents
- explain severity
- identify attack types
- explain suspicious logs
- recommend mitigation actions
"""

    def process_query(self, user_query):

        casual_inputs = [
            "hi",
            "hello",
            "hey"
        ]

        if user_query.lower().strip() in casual_inputs:

            return (
                "Hello. I am your SOC AI assistant. "
                "Ask me about the current incident, "
                "attack severity, suspicious logs, or mitigation steps."
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
            ],

            options={
                "temperature": 0.3,
                "num_predict": 500
            }
        )

        return response["message"]["content"]