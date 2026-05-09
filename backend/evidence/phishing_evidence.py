class PhishingEvidenceEngine:

    def extract(self, dataframe):

        evidence = {

            "MaliciousURLs": 0,

            "CredentialHarvesting": 0,

            "SuspiciousDomains": 0
        }

        # -----------------------------------
        # MALICIOUS URLS
        # -----------------------------------

        if "Label" in dataframe.columns:

            bad_urls = dataframe[

                dataframe["Label"] == "bad"
            ]

            evidence["MaliciousURLs"] = len(
                bad_urls
            )

        # -----------------------------------
        # CREDENTIAL HARVESTING
        # -----------------------------------

        if evidence["MaliciousURLs"] > 20:

            evidence["CredentialHarvesting"] = 1

        # -----------------------------------
        # DOMAIN IMPERSONATION
        # -----------------------------------

        if "URL" in dataframe.columns:

            suspicious = dataframe[

                dataframe["URL"].str.contains(
                    "paypal|login|verify|account",

                    case=False,

                    na=False
                )
            ]

            evidence["SuspiciousDomains"] = len(
                suspicious
            )

        return evidence