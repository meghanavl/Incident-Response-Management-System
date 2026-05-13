import ollama


class SOCChatEngine:

    def __init__(

        self,

        results
    ):

        self.results = results

        self.evidence = results.get(
            "evidence",
            {}
        )

        self.profile = results.get(
            "dataset_profile",
            {}
        )

        self.bayesian = results.get(
            "bayesian_analysis",
            {}
        )

        self.attack_mapping = results.get(
            "attack_mapping",
            []
        )

        self.kill_chain = results.get(
            "kill_chain",
            []
        )

        self.severity = results.get(
            "severity",
            "UNKNOWN"
        )

        self.ueba = results.get(
            "ueba_results",
            {}
        )

        self.timeline = results.get(
            "timeline",
            []
        )

    # =================================================
    # FORMATTERS
    # =================================================

    def _format_attack_mapping(self):

        if not self.attack_mapping:

            return "No ATT&CK techniques detected."

        formatted = []

        for attack in self.attack_mapping:

            formatted.append(

                f"{attack['technique']} "
                f"{attack['name']} "
                f"({attack['tactic']})"
            )

        return "\n".join(formatted)

    def _format_timeline(self):

        if not self.timeline:

            return "No timeline events."

        return "\n".join(
            self.timeline[:10]
        )

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
                f"SOC assistant active for "
                f"{self.profile.get('domain', 'security analysis')}."
            )

        return None

    # =================================================
    # QUERY ROUTER
    # =================================================

    def retrieve_context(

        self,

        query
    ):

        query = query.lower()

        # =============================================
        # SUMMARY
        # =============================================

        if "summary" in query:

            return f"""
SEVERITY: {self.severity}

THREAT PROBABILITY:
{self.bayesian.get('probability', 0)}%

MITRE:
{self._format_attack_mapping()}

KILL CHAIN:
{', '.join(self.kill_chain)}

TOP TIMELINE EVENTS:
{self._format_timeline()}
"""

        # =============================================
        # MITRE
        # =============================================

        elif (
            "mitre" in query
            or "attack" in query
        ):

            return f"""
MITRE ATT&CK TECHNIQUES:

{self._format_attack_mapping()}
"""

        # =============================================
        # KILL CHAIN
        # =============================================

        elif (
            "kill chain" in query
            or "phase" in query
        ):

            return f"""
KILL CHAIN PHASES:

{', '.join(self.kill_chain)}
"""

        # =============================================
        # UEBA
        # =============================================

        elif (
            "ueba" in query
            or "user" in query
            or "risk" in query
        ):

            return f"""
UEBA RESULTS:

{self.ueba}
"""

        # =============================================
        # TIMELINE
        # =============================================

        elif "timeline" in query:

            return f"""
TIMELINE EVENTS:

{self._format_timeline()}
"""

        # =============================================
        # EVIDENCE
        # =============================================

        elif (
            "evidence" in query
            or "suspicious" in query
        ):

            return f"""
SECURITY EVIDENCE:

{self.evidence}
"""

        # =============================================
        # SEVERITY
        # =============================================

        elif "severity" in query:

            return f"""
SEVERITY:
{self.severity}

THREAT PROBABILITY:
{self.bayesian.get('probability', 0)}%
"""

        # =============================================
        # DEFAULT
        # =============================================

        return f"""
DATASET:
{self.profile.get('name', 'Unknown')}

DOMAIN:
{self.profile.get('domain', 'Unknown')}

SEVERITY:
{self.severity}

THREAT PROBABILITY:
{self.bayesian.get('probability', 0)}%
"""

    # =================================================
    # MAIN PROCESSING
    # =================================================

    def process_query(

        self,

        user_query
    ):

        # =============================================
        # QUICK RESPONSE
        # =============================================

        fast = self.quick_response(
            user_query
        )

        if fast:

            return fast

        # =============================================
        # CONTEXT
        # =============================================

        retrieved_context = (

            self.retrieve_context(
                user_query
            )
        )

        # =============================================
        # STRICT SYSTEM PROMPT
        # =============================================

        system_prompt = f"""
You are a SOC incident assistant.

ONLY answer using the provided incident context.

DO NOT:
- invent stories
- generate tutorials
- generate articles
- explain cybersecurity concepts
- add introductions
- add conclusions

STRICT OUTPUT RULES:
- maximum 4 bullet points
- each bullet under 12 words
- no paragraphs
- no headings
- concise SOC analyst language only

If context lacks information:
respond exactly:
No relevant incident evidence found.

INCIDENT CONTEXT:
{retrieved_context}
"""

        # =============================================
        # OLLAMA
        # =============================================

        try:

            response = ollama.chat(

                model="phi3",

                options={

                    "temperature": 0.1,

                    "top_p": 0.2,

                    "num_predict": 120
                },

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

            content = response[
                "message"
            ][
                "content"
            ].strip()

            # =========================================
            # FALLBACK CLEANUP
            # =========================================

            if len(content) > 1000:

                return (
                    "• Excessive model output suppressed.\n"
                    "• Refine investigation query."
                )

            return content

        except Exception as e:

            return (
                f"• SOC assistant failure\n"
                f"• {str(e)}"
            )