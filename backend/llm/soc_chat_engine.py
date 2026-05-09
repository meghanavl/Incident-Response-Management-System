import ollama


class SOCChatEngine:

    def __init__(

        self,

        results
    ):

        self.results = results

        self.evidence = results["evidence"]

        self.profile = results[
            "dataset_profile"
        ]

        self.bayesian = results[
            "bayesian_analysis"
        ]

        self.attack_mapping = results[
            "attack_mapping"
        ]

        self.kill_chain = results[
            "kill_chain"
        ]

        self.severity = results[
            "severity"
        ]

    # =================================================
    # BUILD CONTEXT
    # =================================================

    def build_context(self):

        return f"""
You are an expert SOC analyst.

You are analyzing cybersecurity telemetry.

DATASET DOMAIN:
{self.profile["domain"]}

DATASET DESCRIPTION:
{self.profile["description"]}

THREAT SEVERITY:
{self.severity}

SECURITY EVIDENCE:
{self.evidence}

BAYESIAN THREAT ANALYSIS:
{self.bayesian}

MITRE ATT&CK MAPPING:
{self.attack_mapping}

CYBER KILL CHAIN PHASES:
{self.kill_chain}

YOUR RESPONSIBILITIES:

- Analyze attacker behavior
- Explain security findings
- Explain probable attacker objectives
- Explain incident severity
- Reference MITRE ATT&CK techniques
- Reference kill chain phases
- Recommend incident response actions
- Answer like a SOC analyst

RESPONSE RULES:

- Maximum 5 bullet points
- Concise operational language
- NO large paragraphs
- NO generic AI assistant phrasing
- Focus on actionable insights
- Reference the dataset domain when relevant
- Base conclusions ONLY on provided telemetry
"""

    # =================================================
    # QUERY PROCESSING
    # =================================================

    def process_query(

        self,

        user_query
    ):

        # ---------------------------------------------
        # GREETING HANDLER
        # ---------------------------------------------

        greetings = [

            "hi",
            "hello",
            "hey",
            "good morning",
            "good evening"
        ]

        if user_query.lower().strip() in greetings:

            return (
                f"Hello. SOC AI Assistant active for "
                f"{self.profile['domain']} telemetry. "
                f"Ask about threats, ATT&CK mapping, "
                f"severity analysis, or response actions."
            )

        # ---------------------------------------------
        # OLLAMA RESPONSE
        # ---------------------------------------------

        response = ollama.chat(

            model="phi3:mini",

            messages=[

                {
                    "role": "system",

                    "content":
                    self.build_context()
                },

                {
                    "role": "user",

                    "content":
                    user_query
                }
            ]
        )

        return response["message"]["content"]