from models.security_event import SecurityEvent


class EventNormalizer:

    def normalize(self, dataframe):

        events = []

        for _, row in dataframe.iterrows():

            event = SecurityEvent(

                timestamp=str(row["date"]),
                user=str(row["user"]),
                host=str(row["pc"]),
                activity=str(row["activity"])

            )

            events.append(event)

        # -----------------------------------
        # SORT EVENTS CHRONOLOGICALLY
        # -----------------------------------

        events = sorted(

            events,

            key=lambda x: x.timestamp
        )

        return events