class NetworkIOCEngine:

    def extract(self, dataframe):

        # -----------------------------------
        # CLEAN COLUMNS
        # -----------------------------------

        dataframe.columns = (
            dataframe.columns.str.strip()
        )

        # -----------------------------------
        # IOC OBJECT
        # -----------------------------------

        iocs = {

            "TopSourceIPs": {},

            "TopDestinationPorts": {},

            "ProtocolUsage": {},

            "AttackLabels": {}
        }

        # -----------------------------------
        # SOURCE IPS
        # -----------------------------------

        if "Source Port" in dataframe.columns:

            top_sources = (

                dataframe["Source Port"]

                .value_counts()

                .head(5)
            )

            iocs["TopSourceIPs"] = (
                top_sources.to_dict()
            )

        # -----------------------------------
        # DESTINATION PORTS
        # -----------------------------------

        if "Destination Port" in dataframe.columns:

            top_ports = (

                dataframe["Destination Port"]

                .value_counts()

                .head(5)
            )

            iocs["TopDestinationPorts"] = (
                top_ports.to_dict()
            )

        # -----------------------------------
        # PROTOCOLS
        # -----------------------------------

        if "Protocol" in dataframe.columns:

            protocols = (

                dataframe["Protocol"]

                .value_counts()

                .head(5)
            )

            iocs["ProtocolUsage"] = (
                protocols.to_dict()
            )

        # -----------------------------------
        # ATTACK LABELS
        # -----------------------------------

        if "Label" in dataframe.columns:

            labels = (

                dataframe["Label"]

                .value_counts()

                .head(10)
            )

            iocs["AttackLabels"] = (
                labels.to_dict()
            )

        return iocs