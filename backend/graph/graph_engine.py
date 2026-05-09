import random

import networkx as nx

import matplotlib.pyplot as plt


class GraphEngine:

    def __init__(

        self,

        events,

        evidence
    ):

        self.events = events

        self.evidence = evidence

    # =================================================
    # BUILD GRAPH
    # =================================================

    def build_graph(self):

        graph = nx.DiGraph()

        if not self.events:

            return graph

        dataset_type = self.events[0].dataset_type

        # =================================================
        # CMU CERT
        # USER ↔ HOST RELATIONSHIPS
        # =================================================

        if dataset_type == "CMU_CERT":

            for event in self.events[:40]:

                user_node = (
                    f"USER:{event.user}"
                )

                host_node = (
                    f"HOST:{event.host}"
                )

                graph.add_node(

                    user_node,

                    color="skyblue"
                )

                graph.add_node(

                    host_node,

                    color="lightgreen"
                )

                graph.add_edge(

                    user_node,

                    host_node
                )

                # -----------------------------------------
                # HIGH RISK HOSTS
                # -----------------------------------------

                if event.host in self.evidence.get(

                    "HighRiskHosts",

                    []
                ):

                    alert_node = (
                        f"ALERT:{event.host}"
                    )

                    graph.add_node(

                        alert_node,

                        color="red"
                    )

                    graph.add_edge(

                        host_node,

                        alert_node
                    )

        # =================================================
        # CIC IDS2017
        # IP COMMUNICATION GRAPH
        # =================================================

        elif dataset_type == "CIC_IDS2017":

            for event in self.events[:40]:

                src_node = (
                    f"SRC:{event.src_ip}"
                )

                dst_node = (
                    f"DST:{event.dst_ip}"
                )

                graph.add_node(

                    src_node,

                    color="orange"
                )

                graph.add_node(

                    dst_node,

                    color="lightgreen"
                )

                graph.add_edge(

                    src_node,

                    dst_node
                )

                # -----------------------------------------
                # BOTNET / DOS ALERTS
                # -----------------------------------------

                if self.evidence.get(
                    "BotnetActivity",
                    0
                ):

                    alert_node = (
                        f"BOTNET_ALERT"
                    )

                    graph.add_node(

                        alert_node,

                        color="red"
                    )

                    graph.add_edge(

                        src_node,

                        alert_node
                    )

                if self.evidence.get(
                    "PotentialDoS",
                    0
                ) > 10:

                    dos_node = (
                        "DOS_ACTIVITY"
                    )

                    graph.add_node(

                        dos_node,

                        color="purple"
                    )

                    graph.add_edge(

                        src_node,

                        dos_node
                    )

        # =================================================
        # PHISHING
        # DOMAIN REPUTATION GRAPH
        # =================================================

        elif dataset_type == "PHISHING":

            for event in self.events[:40]:

                url = str(event.url)

                short_url = url[:40]

                url_node = (
                    f"URL:{short_url}"
                )

                graph.add_node(

                    url_node,

                    color="gold"
                )

                label = str(event.label).lower()

                if label == "bad":

                    malicious_node = (
                        "MALICIOUS_DOMAIN"
                    )

                    graph.add_node(

                        malicious_node,

                        color="red"
                    )

                    graph.add_edge(

                        url_node,

                        malicious_node
                    )

                else:

                    benign_node = (
                        "BENIGN_DOMAIN"
                    )

                    graph.add_node(

                        benign_node,

                        color="lightgreen"
                    )

                    graph.add_edge(

                        url_node,

                        benign_node
                    )

        return graph

    # =================================================
    # DRAW GRAPH
    # =================================================

    def draw_graph(self):

        graph = self.build_graph()

        plt.figure(figsize=(14, 8))

        pos = nx.spring_layout(

            graph,

            seed=random.randint(1, 9999),

            k=1.8
        )

        node_colors = []

        for node in graph.nodes():

            node_colors.append(

                graph.nodes[node].get(
                    "color",
                    "skyblue"
                )
            )

        nx.draw(

            graph,

            pos,

            with_labels=True,

            node_color=node_colors,

            node_size=2500,

            font_size=7,

            arrows=True,

            edge_color="gray"
        )

        plt.title(

            "SOC Threat Correlation Graph",

            fontsize=16
        )

        return plt