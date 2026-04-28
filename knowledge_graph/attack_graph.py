import networkx as nx
import matplotlib.pyplot as plt


class AttackKnowledgeGraph:

    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph(self):
        # Indicators
        indicators = [
            "Multiple Failed Logins",
            "Suspicious Email Attachment",
            "Unusual PowerShell Execution",
            "Large Outbound Traffic"
        ]

        # Attacks
        attacks = [
            "Brute Force Attack",
            "Phishing Attack",
            "Malware Execution",
            "Data Exfiltration"
        ]

        # Mitigations
        mitigations = [
            "Lock Account",
            "User Awareness Training",
            "Isolate Host Machine",
            "Block Network Traffic"
        ]

        # Add nodes
        for i in indicators:
            self.graph.add_node(i, type="indicator")

        for a in attacks:
            self.graph.add_node(a, type="attack")

        for m in mitigations:
            self.graph.add_node(m, type="mitigation")

        # Relationships
        self.graph.add_edge("Multiple Failed Logins", "Brute Force Attack")
        self.graph.add_edge("Suspicious Email Attachment", "Phishing Attack")
        self.graph.add_edge("Unusual PowerShell Execution", "Malware Execution")
        self.graph.add_edge("Large Outbound Traffic", "Data Exfiltration")

        self.graph.add_edge("Brute Force Attack", "Lock Account")
        self.graph.add_edge("Phishing Attack", "User Awareness Training")
        self.graph.add_edge("Malware Execution", "Isolate Host Machine")
        self.graph.add_edge("Data Exfiltration", "Block Network Traffic")

    def visualize(self):
        plt.figure(figsize=(10,7))
        pos = nx.spring_layout(self.graph)
        nx.draw(self.graph, pos, with_labels=True, node_color="lightblue", node_size=2500)
        plt.title("Cyber Attack Knowledge Graph")
        plt.show()


if __name__ == "__main__":
    akg = AttackKnowledgeGraph()
    akg.build_graph()
    akg.visualize()