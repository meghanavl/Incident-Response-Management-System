import networkx as nx
import matplotlib.pyplot as plt


class GraphEngine:

    def build_graph(

        self,

        events,

        dataset_name
    ):

        # =====================================
        # DEBUGGING
        # =====================================

        print("\n==============================")
        print("GRAPH ENGINE DEBUG")
        print("==============================")
        print("DATASET:", dataset_name)
        print("TOTAL EVENTS:", len(events))

        if len(events) > 0:

            print("FIRST EVENT:")
            print(vars(events[0]))

        # =====================================
        # GRAPH OBJECT
        # =====================================

        G = nx.Graph()

        # =====================================
        # CMU CERT
        # USER -> HOST -> ACTIVITY
        # =====================================

        if "CMU" in dataset_name:

            for event in events[:40]:

                if not event.user or not event.host:
                    continue

                user_node = f"USER:{event.user}"

                host_node = f"HOST:{event.host}"

                activity_node = f"ACT:{event.activity}"

                # ---------------------------------
                # NODE COLORS
                # ---------------------------------

                G.add_node(
                    user_node,
                    color="skyblue"
                )

                G.add_node(
                    host_node,
                    color="lightgreen"
                )

                suspicious_keywords = [

                    "usb",
                    "file copy",
                    "logon",
                    "http"
                ]

                activity_color = "orange"

                for keyword in suspicious_keywords:

                    if keyword in str(
                        event.activity
                    ).lower():

                        activity_color = "red"

                G.add_node(
                    activity_node,
                    color=activity_color
                )

                # ---------------------------------
                # RELATIONSHIPS
                # ---------------------------------

                G.add_edge(
                    user_node,
                    host_node
                )

                G.add_edge(
                    host_node,
                    activity_node
                )

        # =====================================
        # CIC IDS2017
        # PORT -> ATTACK CATEGORY
        # =====================================

        elif "CIC" in dataset_name:

            for event in events[:60]:

                if not event.protocol:
                    continue

                port_node = (
                    f"PORT:{event.protocol}"
                )

                attack_node = (
                    f"ATTACK:{event.activity}"
                )

                # ---------------------------------
                # PORT NODE
                # ---------------------------------

                G.add_node(

                    port_node,

                    color="orange"
                )

                # ---------------------------------
                # ATTACK NODE
                # ---------------------------------

                label = str(
                    event.activity
                ).lower()

                if "benign" in label:

                    attack_color = "lightgreen"

                else:

                    attack_color = "red"

                G.add_node(

                    attack_node,

                    color=attack_color
                )

                # ---------------------------------
                # RELATIONSHIP
                # ---------------------------------

                G.add_edge(

                    port_node,

                    attack_node
                )

        # =====================================
        # PHISHING
        # DOMAIN -> BRAND -> TLD
        # =====================================

        elif "PHISHING" in dataset_name.upper():

            suspicious_keywords = [

                "paypal",
                "bank",
                "login",
                "verify",
                "account",
                "secure",
                "update",
                "apple",
                "amazon",
                "microsoft"
            ]

            for event in events[:50]:

                if not event.url:
                    continue

                url = str(event.url).lower()

                url_node = url[:35]

                label = str(
                    event.label
                ).lower()

                # ---------------------------------
                # URL NODE COLOR
                # ---------------------------------

                if "bad" in label:

                    url_color = "red"

                else:

                    url_color = "gold"

                G.add_node(

                    url_node,

                    color=url_color
                )

                # =================================
                # BRAND / KEYWORD CORRELATION
                # =================================

                for keyword in suspicious_keywords:

                    if keyword in url:

                        keyword_node = (
                            f"KW:{keyword.upper()}"
                        )

                        G.add_node(

                            keyword_node,

                            color="violet"
                        )

                        G.add_edge(

                            url_node,

                            keyword_node
                        )

                # =================================
                # TLD CORRELATION
                # =================================

                tlds = [

                    ".ru",
                    ".tk",
                    ".biz",
                    ".cn",
                    ".xyz",
                    ".com"
                ]

                for tld in tlds:

                    if tld in url:

                        tld_node = (
                            f"TLD:{tld}"
                        )

                        G.add_node(

                            tld_node,

                            color="cyan"
                        )

                        G.add_edge(

                            url_node,

                            tld_node
                        )

        # =====================================
        # EMPTY SAFETY
        # =====================================

        fig, ax = plt.subplots(

            figsize=(15, 10)
        )

        if G.number_of_nodes() == 0:

            ax.text(

                0.5,
                0.5,

                "No graph data available",

                ha="center",

                fontsize=14
            )

            return fig

        # =====================================
        # GRAPH DRAWING
        # =====================================

        colors = [

            G.nodes[node]["color"]

            for node in G.nodes()
        ]

        pos = nx.spring_layout(

            G,

            seed=42,

            k=2.4
        )

        nx.draw(

            G,

            pos,

            ax=ax,

            with_labels=True,

            node_color=colors,

            node_size=700,

            font_size=6,

            edge_color="gray",

            alpha=0.85
        )

        # =====================================
        # DYNAMIC TITLES
        # =====================================

        if "CMU" in dataset_name:

            title = (
                "User-Host Behavioral Relationship Graph"
            )

        elif "CIC" in dataset_name:

            title = (
                "Network Attack Surface Communication Graph"
            )

        elif "PHISHING" in dataset_name.upper():

            title = (
                "Phishing Campaign Infrastructure Graph"
            )

        else:

            title = (
                "SOC Threat Correlation Graph"
            )

        ax.set_title(

            title,

            fontsize=16
        )

        return fig