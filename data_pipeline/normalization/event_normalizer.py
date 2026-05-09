from models.security_event import SecurityEvent


class EventNormalizer:
    def normalize(
        self,
        dataframe,
        dataset_name
    ):
        events = []
        # -----------------------------------
        # CMU CERT
        # -----------------------------------

        if dataset_name == "CMU_CERT":
            for _, row in dataframe.iterrows():
                event = SecurityEvent(
                    timestamp=str(row["date"]),
                    user=str(row["user"]),
                    host=str(row["pc"]),
                    activity=str(row["activity"]),
                    dataset_type="CMU_CERT"
                )

                events.append(event)

        # -----------------------------------
        # CIC IDS 2017
        # -----------------------------------

        elif dataset_name == "CIC_IDS2017":
            for _, row in dataframe.iterrows():
                event = SecurityEvent(
                    src_ip=str(row.iloc[1]),
                    dst_ip=str(row.iloc[3]),
                    protocol=str(row.iloc[5]),
                    activity="Network Traffic",
                    dataset_type="CIC_IDS2017"
                )

                events.append(event)

        # -----------------------------------
        # PHISHING
        # -----------------------------------

        elif dataset_name == "PHISHING":

            for _, row in dataframe.iterrows():
                event = SecurityEvent(
                    url=str(row["URL"]),
                    label=str(row["Label"]),
                    activity="Phishing URL",
                    dataset_type="PHISHING"
                )
                events.append(event)
        return events