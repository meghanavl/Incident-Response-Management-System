import networkx as nx
import matplotlib.pyplot as plt


class GraphEngine:

    def __init__(self, events, evidence):

        self.events = events

        self.evidence = evidence

    def build_graph(self):

        graph = nx.DiGraph()

        # -----------------------------------
        # IDENTIFY SUSPICIOUS USERS
        # -----------------------------------

        user_activity = {}

        for event in self.events:

            user_activity[event.user] = (
                user_activity.get(event.user, 0) + 1
            )

        high_risk_users = [

            user

            for user, count

            in user_activity.items()

            if count > 2
        ]

        suspicious_hosts = set(
            self.evidence["HighRiskHosts"]
        )

        # -----------------------------------
        # FILTER IMPORTANT EVENTS ONLY
        # -----------------------------------

        filtered_events = [

            event

            for event in self.events

            if (

                event.user in high_risk_users

                or

                event.host in suspicious_hosts
            )
        ]

        # LIMIT GRAPH SIZE
        filtered_events = filtered_events[:30]

        users_seen = {}

        previous_event = None

        # -----------------------------------
        # BUILD RELATIONSHIPS
        # -----------------------------------

        for event in filtered_events:

            user_node = f"USER:{event.user}"

            host_node = f"HOST:{event.host}"

            graph.add_node(

                user_node,
                node_type="user"
            )

            graph.add_node(

                host_node,
                node_type="host"
            )

            # USER → HOST ACCESS

            graph.add_edge(

                user_node,
                host_node,

                edge_type="access"
            )

            # -----------------------------------
            # AUTH ACTIVITY
            # -----------------------------------

            if event.activity.lower() == "logon":

                auth_node = "AUTH_ACTIVITY"

                graph.add_node(

                    auth_node,
                    node_type="auth"
                )

                graph.add_edge(

                    host_node,
                    auth_node,

                    edge_type="auth"
                )

            # -----------------------------------
            # LATERAL MOVEMENT
            # -----------------------------------

            if event.user in users_seen:

                previous_host = (
                    users_seen[event.user]
                )

                if previous_host != event.host:

                    previous_host_node = (
                        f"HOST:{previous_host}"
                    )

                    lateral_node = (
                        f"LATERAL:{event.host}"
                    )

                    graph.add_node(

                        lateral_node,
                        node_type="lateral"
                    )

                    graph.add_edge(

                        previous_host_node,
                        lateral_node,

                        edge_type="lateral"
                    )

                    graph.add_edge(

                        lateral_node,
                        host_node,

                        edge_type="movement"
                    )

            users_seen[event.user] = event.host

            # -----------------------------------
            # TEMPORAL ATTACK PATHS
            # -----------------------------------

            if previous_event:

                previous_host_node = (
                    f"HOST:{previous_event.host}"
                )

                current_host_node = (
                    f"HOST:{event.host}"
                )

                if previous_host_node != current_host_node:

                    graph.add_edge(

                        previous_host_node,
                        current_host_node,

                        edge_type="attack_path"
                    )

            previous_event = event

        # -----------------------------------
        # ALERT NODES
        # -----------------------------------

        for host in suspicious_hosts:

            host_node = f"HOST:{host}"

            alert_node = f"ALERT:{host}"

            graph.add_node(

                alert_node,
                node_type="alert"
            )

            graph.add_edge(

                host_node,
                alert_node,

                edge_type="alert"
            )

        return graph

    def draw_graph(self):

        graph = self.build_graph()

        plt.figure(figsize=(16, 10))

        pos = nx.spring_layout(

            graph,

            seed=42,

            k=3.2
        )

        # -----------------------------------
        # NODE COLORS
        # -----------------------------------

        node_colors = []

        for _, data in graph.nodes(data=True):

            node_type = data.get("node_type")

            if node_type == "alert":

                node_colors.append("red")

            elif node_type == "lateral":

                node_colors.append("orange")

            elif node_type == "host":

                node_colors.append("lightgreen")

            elif node_type == "auth":

                node_colors.append("yellow")

            else:

                node_colors.append("skyblue")

        # -----------------------------------
        # EDGE COLORS
        # -----------------------------------

        edge_colors = []

        for _, _, data in graph.edges(data=True):

            edge_type = data.get("edge_type")

            if edge_type == "alert":

                edge_colors.append("red")

            elif edge_type == "lateral":

                edge_colors.append("orange")

            elif edge_type == "auth":

                edge_colors.append("gold")

            elif edge_type == "attack_path":

                edge_colors.append("purple")

            else:

                edge_colors.append("gray")

        # -----------------------------------
        # DRAW GRAPH
        # -----------------------------------

        nx.draw(

            graph,
            pos,

            with_labels=False,

            node_color=node_colors,

            edge_color=edge_colors,

            node_size=1700,

            width=2,

            alpha=0.85
        )

        # -----------------------------------
        # IMPORTANT LABELS ONLY
        # -----------------------------------

        important_labels = {

            node: node

            for node, data in graph.nodes(data=True)

            if data.get("node_type") in [

                "alert",
                "lateral",
                "host"
            ]
        }

        nx.draw_networkx_labels(

            graph,
            pos,

            labels=important_labels,

            font_size=8
        )

        plt.title(

            "SOC Attack Correlation Graph",

            fontsize=16,

            fontweight="bold"
        )

        plt.axis("off")

        return plt