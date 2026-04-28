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
- Chat-based querying
""")

st.divider()

# -------------------------------
# SIMULATE INCIDENT
# -------------------------------

if st.button("Simulate Security Incident"):

    parser = LogParser()
    logs = parser.generate_sample_logs()

    st.subheader("Generated Logs")
    for log in logs:
        st.code(log)

    evidence = parser.analyze_logs()

    st.subheader("Extracted Evidence")
    st.json(evidence)

    # -------------------------------
    # MODEL
    # -------------------------------

    model = RiskPredictionModel()
    result = model.predict_bruteforce(evidence["FailedLogins"])

    st.subheader("Attack Probability")
    st.write(result)

    # -------------------------------
    # IMPACT PREDICTION (NEW)
    # -------------------------------

    def predict_impact(evidence):
        if evidence["PowerShellExec"]:
            return "HIGH"
        elif evidence["SuspiciousEmail"]:
            return "MEDIUM"
        elif evidence["FailedLogins"]:
            return "LOW"
        return "NONE"

    impact = predict_impact(evidence)

    st.subheader("Impact Level")
    st.write(impact)

    # -------------------------------
    # SOC ACTIONS
    # -------------------------------

    st.subheader("Recommended SOC Actions")

    if evidence["FailedLogins"] == 1:
        st.success("Lock affected accounts and monitor authentication logs.")

    if evidence["SuspiciousEmail"] == 1:
        st.warning("Investigate phishing email and alert users.")

    if evidence["PowerShellExec"] == 1:
        st.error("Isolate the affected machine immediately.")

    # -------------------------------
    # KNOWLEDGE GRAPH
    # -------------------------------

    st.subheader("Attack Knowledge Graph")

    graph = AttackKnowledgeGraph()
    graph.build_graph()

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

# -------------------------------
# CHATBOT (NEW FEATURE)
# -------------------------------

st.divider()
st.subheader("SOC Assistant Chat")

user_input = st.text_input("Ask something (e.g. 'Is this a phishing attack?')")

if user_input:
    user_input = user_input.lower()

    if "phishing" in user_input:
        st.write("Possible phishing attack detected based on suspicious email patterns.")

    elif "brute force" in user_input or "login" in user_input:
        st.write("Multiple failed logins indicate a possible brute force attack.")

    elif "malware" in user_input or "powershell" in user_input:
        st.write("Suspicious PowerShell execution may indicate malware activity.")

    elif "impact" in user_input:
        st.write("Impact is determined based on severity of detected indicators.")

    else:
        st.write("I can help analyze attacks, logs, and mitigation strategies.")