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
from chatbot.soc_chat_engine import SOCChatEngine

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
# SCENARIO
# -------------------------------
scenario = st.selectbox(
    "Select Attack Scenario",
    ["bruteforce", "phishing", "malware", "mixed"]
)

# -------------------------------
# SIMULATION BUTTON
# -------------------------------
if st.button("Simulate Security Incident"):

    parser = LogParser()

    log_placeholder = st.empty()
    all_logs = []

    for log in parser.stream_logs(scenario=scenario):
        all_logs.append(log)
        log_placeholder.code("\n".join(all_logs))

    evidence = parser.analyze_stream()

    model = RiskPredictionModel()

    brute = model.predict_bruteforce(evidence)
    phishing = model.predict_phishing(evidence)
    malware = model.predict_malware(evidence)

    # impact
    if evidence["PowerShellExec"]:
        impact = "HIGH"
    elif evidence["SuspiciousEmail"]:
        impact = "MEDIUM"
    elif evidence["FailedLogins"]:
        impact = "LOW"
    else:
        impact = "NONE"

    # recommendations
    recommendations = model.recommend_from_history(evidence)

    # SAVE EVERYTHING
    st.session_state["logs"] = all_logs
    st.session_state["evidence"] = evidence
    st.session_state["results"] = {
        "brute": brute,
        "phishing": phishing,
        "malware": malware
    }
    st.session_state["impact"] = impact
    st.session_state["recommendations"] = recommendations

    model.save_incident(evidence)

# =====================================================
# 🔥 PERSISTENT UI (THIS FIXES YOUR MAIN ISSUE)
# =====================================================

# LOGS
if "logs" in st.session_state:
    st.subheader("Streaming Logs")
    st.code("\n".join(st.session_state["logs"]))

# EVIDENCE
if "evidence" in st.session_state:
    st.subheader("Extracted Evidence")
    st.json(st.session_state["evidence"])

# RESULTS
if "results" in st.session_state:
    results = st.session_state["results"]

    st.subheader("Attack Probabilities")

    st.write("Brute Force Attack")
    st.write(results["brute"])

    st.write("Phishing Attack")
    st.write(results["phishing"])

    st.write("Malware Execution")
    st.write(results["malware"])

# IMPACT
if "impact" in st.session_state:
    st.subheader("Impact Level")
    st.write(st.session_state["impact"])

# RECOMMENDATIONS
if "recommendations" in st.session_state:
    st.subheader("Recommended Actions")
    for r in st.session_state["recommendations"]:
        st.success(r)

# GRAPH
if "evidence" in st.session_state:
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
        node_size=1000,
        ax=ax
    )

    st.pyplot(fig)

# -------------------------------
# WHY THIS DECISION
# -------------------------------
if "evidence" in st.session_state:
    st.subheader("Why this decision?")

    engine = SOCChatEngine(st.session_state["evidence"])
    explanation = engine.explain_decision()

    st.info(explanation)

# -------------------------------
# CHATBOT
# -------------------------------
st.divider()
st.subheader("SOC Assistant Chat")

user_input = st.text_input("Ask something")

if user_input:
    if "evidence" in st.session_state:
        model = RiskPredictionModel()
        engine = SOCChatEngine(st.session_state["evidence"])

        response = engine.process_query(user_input, model)
        st.write(response)
    else:
        st.warning("Run simulation first.")