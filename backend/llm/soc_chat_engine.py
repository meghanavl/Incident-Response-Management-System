import ollama


class SOCChatEngine:

    def __init__(

        self,

        results
    ):

        self.results = results

        self.evidence = results[
            "evidence"
        ]

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

        self.ueba = results.get(
            "ueba",
            {}
        )

        self.timelines = results.get(
            "user_timelines",
            {}
        )

    # =================================================
    # QUERY ROUTER
    # =================================================

    def retrieve_context(

        self,

        query
    ):

        query = query.lower()

        context = ""

        # ---------------------------------------------
        # SUMMARY
        # ---------------------------------------------

        if "summary" in query:

            context += f"""

SEVERITY:
{self.severity}

THREAT PROBABILITY:
{self.bayesian["probability"]}%

THREAT CONFIDENCE:
{self.bayesian["label"]}
"""

        # ---------------------------------------------
        # MITRE
        # ---------------------------------------------

        elif "mitre" in query \
        or "attack" in query:

            context += f"""

MITRE ATT&CK TECHNIQUES:
{self.attack_mapping}
"""

        # ---------------------------------------------
        # KILL CHAIN
        # ---------------------------------------------

        elif "kill chain" in query \
        or "phase" in query:

            context += f"""

KILL CHAIN PHASES:
{self.kill_chain}
"""

        # ---------------------------------------------
        # UEBA
        # ---------------------------------------------

        elif "ueba" in query \
        or "user" in query \
        or "risk" in query:

            context += f"""

USER BEHAVIOR ANALYTICS:
{self.ueba}
"""

        # ---------------------------------------------
        # TIMELINES
        # ---------------------------------------------

        elif "timeline" in query:

            context += f"""

USER TIMELINES:
{self.timelines}
"""

        # ---------------------------------------------
        # EVIDENCE
        # ---------------------------------------------

        elif "evidence" in query \
        or "suspicious" in query:

            context += f"""

SECURITY EVIDENCE:
{self.evidence}
"""

        # ---------------------------------------------
        # SEVERITY
        # ---------------------------------------------

        elif "severity" in query:

            context += f"""

SEVERITY:
{self.severity}

THREAT PROBABILITY:
{self.bayesian}
"""

        # ---------------------------------------------
        # DEFAULT
        # ---------------------------------------------

        else:

            context += f"""

DATASET DOMAIN:
{self.profile["domain"]}

SEVERITY:
{self.severity}

THREAT PROBABILITY:
{self.bayesian["probability"]}%
"""

        return context

    # =================================================
    # QUICK RESPONSES
    # =================================================

    def quick_response(

        self,

        query
    ):

        query = query.lower().strip()

        greetings = [

            "hi",
            "hello",
            "hey"
        ]

        if query in greetings:

            return (
                f"SOC AI Assistant active for "
                f"{self.profile['domain']} telemetry."
            )

        return None

    # =================================================
    # MAIN PROCESSING
    # =================================================

    def process_query(

        self,

        user_query
    ):

        # ---------------------------------------------
        # QUICK RESPONSE
        # ---------------------------------------------

        fast = self.quick_response(
            user_query
        )

        if fast:

            return fast

        # ---------------------------------------------
        # RETRIEVED CONTEXT
        # ---------------------------------------------

        retrieved_context = (

            self.retrieve_context(
                user_query
            )
        )

        # ---------------------------------------------
        # SYSTEM PROMPT
        # ---------------------------------------------

        system_prompt = f"""
        You are a SOC analyst assistant.

        DATASET DOMAIN:
        {self.profile["domain"]}

        RETRIEVED CONTEXT:
        {retrieved_context}

        STRICT RESPONSE RULES:

        - MAXIMUM 4 bullet points
        - EACH bullet MAXIMUM 12 words
        - NO paragraphs
        - NO explanations
        - NO introductions
        - NO conclusions
        - NO markdown headings
        - NO long sentences
        - Use short SOC alert language
        - Mention MITRE IDs only if relevant
        - Mention severity only if relevant
        - Mention actions briefly

        GOOD RESPONSE EXAMPLE:

        • Suspicious logons exceeded enterprise baseline.
        • Credential abuse indicators detected.
        • MITRE T1078 Valid Accounts observed.
        • Isolate affected endpoints immediately.

        BAD RESPONSE EXAMPLE:

        "This incident indicates a potentially serious compromise..."
        """

        # ---------------------------------------------
        # OLLAMA
        # ---------------------------------------------

        response = ollama.chat(

            model="phi3:mini",

            messages=[

                {
                    "role": "system",

                    "content":
                    system_prompt
                },

                {
                    "role": "user",

                    "content":
                    user_query
                }
            ]
        )

        return response["message"]["content"]