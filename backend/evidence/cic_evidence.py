class CICEvidenceEngine:

    def extract(self, dataframe):

        # -----------------------------------------
        # CLEAN COLUMN NAMES
        # -----------------------------------------

        dataframe.columns = (

            dataframe.columns
            .str.strip()
        )

        # -----------------------------------------
        # EVIDENCE OBJECT
        # -----------------------------------------

        evidence = {

            "SuspiciousFlows": 0,

            "PotentialDoS": 0,

            "BotnetActivity": 0,

            "InfiltrationAttempts": 0
        }

        # -----------------------------------------
        # NORMALIZE LABELS
        # -----------------------------------------

        labels = dataframe["Label"] \
            .astype(str) \
            .str.lower()

        # -----------------------------------------
        # DOS
        # -----------------------------------------

        evidence["PotentialDoS"] = int(

            labels.str.contains(
                "dos"
            ).sum()
        )

        # -----------------------------------------
        # BOTNET
        # -----------------------------------------

        evidence["BotnetActivity"] = int(

            labels.str.contains(
                "bot"
            ).sum()
        )

        # -----------------------------------------
        # INFILTRATION
        # -----------------------------------------

        evidence["InfiltrationAttempts"] = int(

            labels.str.contains(
                "infiltration"
            ).sum()
        )

        # -----------------------------------------
        # SUSPICIOUS FLOWS
        # -----------------------------------------

        suspicious_keywords = [

            "attack",

            "patator",

            "dos",

            "bot",

            "infiltration"
        ]

        suspicious_count = 0

        for keyword in suspicious_keywords:

            suspicious_count += (

                labels.str.contains(
                    keyword
                ).sum()
            )

        evidence["SuspiciousFlows"] = int(
            suspicious_count
        )

        return evidence