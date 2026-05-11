from collections import Counter


class NetworkIOCEngine:

    def analyze(self, dataframe):

        results = {}

        # =====================================
        # ATTACK LABELS
        # =====================================

        if "Label" in dataframe.columns:

            labels = dataframe["Label"].value_counts()

            results["attack_categories"] = (

                labels.to_dict()
            )

            malicious = 0

            total = len(dataframe)

            for label, count in labels.items():

                if str(label).upper() != "BENIGN":

                    malicious += count

            ratio = round(

                (malicious / total) * 100,

                2
            )

            results["malicious_flow_ratio"] = ratio

        else:

            results["attack_categories"] = {}

            results["malicious_flow_ratio"] = 0

        # =====================================
        # TARGETED PORTS
        # =====================================

        if "Destination Port" in dataframe.columns:

            top_ports = (

                dataframe[
                    "Destination Port"
                ]

                .value_counts()

                .head(10)

                .to_dict()
            )

            results["top_ports"] = top_ports

        else:

            results["top_ports"] = {}

        # =====================================
        # FLOW DURATION
        # =====================================

        if "Flow Duration" in dataframe.columns:

            results["avg_flow_duration"] = round(

                dataframe[
                    "Flow Duration"
                ].mean(),

                2
            )

        else:

            results["avg_flow_duration"] = 0

        # =====================================
        # PACKET METRICS
        # =====================================

        if "Total Fwd Packets" in dataframe.columns:

            results["avg_fwd_packets"] = round(

                dataframe[
                    "Total Fwd Packets"
                ].mean(),

                2
            )

        else:

            results["avg_fwd_packets"] = 0

        if "Total Backward Packets" in dataframe.columns:

            results["avg_bwd_packets"] = round(

                dataframe[
                    "Total Backward Packets"
                ].mean(),

                2
            )

        else:

            results["avg_bwd_packets"] = 0

        return results