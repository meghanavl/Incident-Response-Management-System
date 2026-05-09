class CICEvidenceEngine:

    def extract(self, dataframe):

        evidence = {

            "SuspiciousFlows": 0,

            "PotentialDoS": 0,

            "BotnetActivity": 0,

            "InfiltrationAttempts": 0
        }

        # -----------------------------------
        # LONG FLOW DETECTION
        # -----------------------------------

        if "Flow Duration" in dataframe.columns:

            suspicious = dataframe[

                dataframe["Flow Duration"] > 1000000
            ]

            evidence["SuspiciousFlows"] = len(
                suspicious
            )

        # -----------------------------------
        # DOS DETECTION
        # -----------------------------------

        if "Total Fwd Packets" in dataframe.columns:

            dos = dataframe[

                dataframe["Total Fwd Packets"] > 1000
            ]

            evidence["PotentialDoS"] = len(
                dos
            )

        # -----------------------------------
        # BOTNET SIMULATION
        # -----------------------------------

        if evidence["PotentialDoS"] > 10:

            evidence["BotnetActivity"] = 1

        # -----------------------------------
        # INFILTRATION
        # -----------------------------------

        if evidence["SuspiciousFlows"] > 20:

            evidence["InfiltrationAttempts"] = 1

        return evidence