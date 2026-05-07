import random
import networkx as nx
import matplotlib.pyplot as plt


class AttackGraph:

    def __init__(self, logs):

        self.logs = logs

    def build_graph(self):

        graph = nx.DiGraph()

        sampled_logs = self.logs.sample(
            20,
            replace=False
        )

        users_seen = {}

        for _, row in sampled_logs.iterrows():

            user = str(row["user"])

            host = str(row["pc"])

            activity = str(row["activity"])

            user_node = f"USER:{user}"

            host_node = f"HOST:{host}"

            graph.add_node(user_node)

            graph.add_node(host_node)

            graph.add_edge(
                user_node,
                host_node
            )

            if activity.lower() == "logon":

                graph.add_node(
                    "AUTH_ACTIVITY"
                )

                graph.add_edge(
                    host_node,
                    "AUTH_ACTIVITY"
                )

            if user in users_seen:

                previous_host = users_seen[user]

                if previous_host != host:

                    lateral_node = (
                        f"LATERAL_MOVE:{host}"
                    )

                    graph.add_node(
                        lateral_node
                    )

                    graph.add_edge(
                        previous_host,
                        lateral_node
                    )

                    graph.add_edge(
                        lateral_node,
                        host_node
                    )

            users_seen[user] = host

            if random.random() > 0.7:

                alert_node = (
                    f"ALERT:{host}"
                )

                graph.add_node(alert_node)

                graph.add_edge(
                    host_node,
                    alert_node
                )

        return graph

    def draw_graph(self):

        graph = self.build_graph()

        plt.figure(figsize=(14, 8))

        pos = nx.spring_layout(
            graph,
            seed=random.randint(1, 9999),
            k=1.5
        )

        node_colors = []

        for node in graph.nodes():

            if "ALERT" in node:

                node_colors.append("red")

            elif "LATERAL" in node:

                node_colors.append("orange")

            elif "HOST" in node:

                node_colors.append("lightgreen")

            else:

                node_colors.append("skyblue")

        nx.draw(
            graph,
            pos,
            with_labels=True,
            node_color=node_colors,
            node_size=2000,
            font_size=7,
            arrows=True
        )

        return plt