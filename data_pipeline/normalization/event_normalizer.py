from models.security_event import SecurityEvent


class EventNormalizer:

    def normalize(

        self,

        dataframe,

        dataset_name
    ):

        events = []

        # =====================================
        # CLEAN COLUMN NAMES
        # =====================================

        dataframe.columns = (

            dataframe.columns

            .str.strip()
        )

        # =====================================
        # CMU CERT
        # =====================================

        if dataset_name == "CMU_CERT":

            for _, row in dataframe.iterrows():

                event = SecurityEvent(

                    timestamp=str(

                        row.get("date", "")
                    ),

                    user=str(

                        row.get("user", "")
                    ),

                    host=str(

                        row.get("pc", "")
                    ),

                    activity=str(

                        row.get(
                            "activity",
                            "Unknown"
                        )
                    ),

                    dataset_type="CMU_CERT"
                )

                events.append(event)

        # =====================================
        # CIC IDS 2017
        # =====================================

        elif dataset_name == "CIC_IDS2017":

            for _, row in dataframe.iterrows():

                event = SecurityEvent(

                    src_ip=str(

                        row.get(
                            "Source IP",
                            row.iloc[1]
                        )
                    ),

                    dst_ip=str(

                        row.get(
                            "Destination IP",
                            row.iloc[3]
                        )
                    ),

                    protocol=str(

                        row.get(
                            "Destination Port",
                            row.iloc[0]
                        )
                    ),

                    activity=str(

                        row.get(
                            "Label",
                            "Network Traffic"
                        )
                    ),

                    dataset_type="CIC_IDS2017"
                )

                events.append(event)

        # =====================================
        # PHISHING
        # =====================================

        elif dataset_name == "PHISHING":

            for _, row in dataframe.iterrows():

                event = SecurityEvent(

                    url=str(

                        row.get(
                            "URL",
                            ""
                        )
                    ),

                    label=str(

                        row.get(
                            "Label",
                            ""
                        )
                    ),

                    activity="Phishing URL",

                    dataset_type="PHISHING"
                )

                events.append(event)

        return events