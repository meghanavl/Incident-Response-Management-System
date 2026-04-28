import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
import matplotlib.pyplot as plt
import networkx as nx

from evidence_collection.log_parser import LogParser
from bayesian_model.risk_model import RiskPredictionModel
from knowledge_graph.attack_graph import AttackKnowledgeGraph


st.set_page_config(page_title="SOC Incident Response Assistant", layout="wide")

st.title("SOC Incident Response Decision Support System")

st.write("""
This AI assistant helps SOC analysts during security incidents.

Features:
- Detect attack indicators from logs
- Predict attack probability
- Recommend mitigation actions
- Visualize attack graph
""")

st.divider()


if st.button("Simulate Security Incident"):

    parser = LogParser()
    logs = parser.generate_sample_logs()

    st.subheader("Generated Logs")
    for log in logs:
        st.code(log)

    evidence = parser.analyze_logs()

    st.subheader("Extracted Evidence")
    st.json(evidence)

    model = RiskPredictionModel()
    result = model.predict_bruteforce(evidence["FailedLogins"])

    st.subheader("Attack Probability")
    st.write(result)

    st.subheader("Recommended SOC Actions")

    if evidence["FailedLogins"] == 1:
        st.success("Lock affected accounts and monitor authentication logs.")

    if evidence["SuspiciousEmail"] == 1:
        st.warning("Investigate phishing email and alert users.")

    if evidence["PowerShellExec"] == 1:
        st.error("Isolate the affected machine immediately.")

    graph = AttackKnowledgeGraph()
    graph.build_graph()

    st.subheader("Attack Knowledge Graph")

    fig, ax = plt.subplots(figsize=(10, 7))
    pos = nx.spring_layout(graph.graph)

    nx.draw(
        graph.graph,
        pos,
        with_labels=True,
        node_color="lightblue",
        node_size=2500,
        ax=ax
    )

    st.pyplot(fig)