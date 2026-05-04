# file: soc_chatbot.py

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
# SELECT SCENARIO
# -------------------------------
scenario = st.selectbox(
    "Select Attack Scenario",
    ["bruteforce", "phishing", "malware", "mixed"]
)

# -------------------------------
# BUTTON
# -------------------------------
if st.button("Simulate Security Incident"):

    parser = LogParser()

    st.subheader("Streaming Logs")

    log_placeholder = st.empty()
    all_logs = []

    for log in parser.stream_logs(scenario=scenario):
        all_logs.append(log)
        log_placeholder.code("\n".join(all_logs))

    # -------------------------------
    # ANALYZE
    # -------------------------------
    evidence = parser.analyze_stream()
    st.session_state["evidence"] = evidence

    st.subheader("Extracted Evidence:")
    st.json(evidence)

    # -------------------------------
    # MODEL
    # -------------------------------
    model = RiskPredictionModel()

    brute_result = model.predict_bruteforce(evidence)
    phishing_result = model.predict_phishing(evidence)
    malware_result = model.predict_malware(evidence)

    model.save_incident(evidence)

    # -------------------------------
    # OUTPUT
    # -------------------------------
    st.subheader("Attack Probabilities:")

    st.write("Brute Force Attack")
    st.write(brute_result)

    st.write("Phishing Attack")
    st.write(phishing_result)

    st.write("Malware Execution")
    st.write(malware_result)

    # -------------------------------
    # IMPACT
    # -------------------------------
    def predict_impact(e):
        if e["PowerShellExec"]:
            return "HIGH"
        elif e["SuspiciousEmail"]:
            return "MEDIUM"
        elif e["FailedLogins"]:
            return "LOW"
        return "NONE"

    impact = predict_impact(evidence)

    st.subheader("Impact Level:")
    st.write(impact)

    # -------------------------------
    # ACTIONS
    # -------------------------------
    st.subheader("Recommended Actions:")

    if evidence["FailedLogins"]:
        st.success("Lock affected accounts and monitor authentication logs.")

    if evidence["SuspiciousEmail"]:
        st.warning("Investigate phishing email and alert users.")

    if evidence["PowerShellExec"]:
        st.error("Isolate the affected machine immediately.")

    # -------------------------------
    # GRAPH
    # -------------------------------
    st.subheader("Attack Knowledge Graph:")

    graph = AttackKnowledgeGraph()
    graph.build_graph()

    fig, ax = plt.subplots(figsize=(10, 7))
    pos = nx.spring_layout(graph.graph)

    nx.draw(
        graph.graph,
        pos,
        with_labels=True,
        node_color="lightblue",
        node_size=1000,
        ax=ax
    )

    st.pyplot(fig)



st.subheader("Why this decision?")

from chatbot.soc_chat_engine import SOCChatEngine

if "evidence" in st.session_state:
    engine = SOCChatEngine(st.session_state["evidence"])

    explanation = engine.explain_decision()
    st.info(explanation)
else:
    st.warning("Please simulate an incident first.")
# -------------------------------
# CHATBOT
# -------------------------------
from chatbot.soc_chat_engine import SOCChatEngine

st.divider()
st.subheader("SOC Assistant Chat:")

user_input = st.text_input("Ask something")

if user_input:
    try:
        if "evidence" in st.session_state:
            engine = SOCChatEngine(st.session_state["evidence"])
            response = engine.process_query(user_input)
            st.write(response)
        else:
            st.warning("Run simulation first.")
        response = engine.process_query(user_input)
        st.write(response)
    except:
        st.write("Run simulation first to generate evidence.")