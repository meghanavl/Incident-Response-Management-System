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

st.set_page_config(
    page_title="SOC Incident Response Assistant",
    layout="wide"
)

st.title("SOC Incident Response Decision Support System")

st.write("""
This system assists SOC analysts during security incidents by:

- Detecting attack indicators from predefined logs
- Predicting attack probability
- Recommending mitigation actions
- Historical incident learning
- Knowledge graph visualization
- Chat-based querying
""")

st.divider()

# ------------------------------------------------
# SCENARIO SELECTION
# ------------------------------------------------
scenario = st.selectbox(
    "Select Attack Scenario",
    [
        "Bruteforce",
        "Phishing",
        "Malware",
        "Exfiltration",
        "Mixed"
    ]
)

# ------------------------------------------------
# SIMULATION 
# ------------------------------------------------
if st.button("Simulate Security Incident"):

    parser = LogParser()
    all_logs = []
    for log in parser.stream_logs(scenario=scenario):
        all_logs.append(log)

    # ------------------------------------------------
    # EVIDENCE EXTRACTION
    # ------------------------------------------------
    evidence = parser.analyze_stream()

    # ------------------------------------------------
    # MODEL
    # ------------------------------------------------
    model = RiskPredictionModel()

    brute = model.predict_bruteforce(evidence)

    phishing = model.predict_phishing(evidence)

    malware = model.predict_malware(evidence)

    exfiltration = model.predict_exfiltration(evidence)

    # ------------------------------------------------
    # IMPACT
    # ------------------------------------------------
    if evidence.get("DataExfiltrationPattern"):
        impact = "CRITICAL"

    elif evidence.get("PowerShellExec"):
        impact = "HIGH"

    elif evidence.get("SuspiciousEmail"):
        impact = "MEDIUM"

    elif evidence.get("FailedLogins"):
        impact = "LOW"

    else:
        impact = "NONE"


    recommendations = model.recommend_from_history(evidence)


    model.save_incident(evidence)

    # ------------------------------------------------
    # SESSION STATE
    # ------------------------------------------------
    st.session_state["logs"] = all_logs

    st.session_state["evidence"] = evidence

    st.session_state["results"] = {
        "brute": brute,
        "phishing": phishing,
        "malware": malware,
        "exfiltration": exfiltration
    }

    st.session_state["impact"] = impact

    st.session_state["recommendations"] = recommendations

# ====================================================
# PERSISTENT UI
# ====================================================

# ------------------------------------------------
# LOGS
# ------------------------------------------------
if "logs" in st.session_state:

    st.subheader("Streaming Logs")

    st.code(
        "\n".join(
            st.session_state["logs"]
        )
    )

# ------------------------------------------------
# EVIDENCE
# ------------------------------------------------
if "evidence" in st.session_state:

    st.subheader("Extracted Evidence")

    st.json(st.session_state["evidence"])
else:
    st.info(
        "No incident evidence available yet."
        "Run a security incident simulation first."
    )

# ------------------------------------------------
# RESULTS
# ------------------------------------------------
if "results" in st.session_state:

    results = st.session_state["results"]

    st.subheader("Attack Probabilities")

    st.write("Brute Force Attack: ")
    st.write(results["brute"])

    st.write("Phishing Attack: ")
    st.write(results["phishing"])

    st.write("Malware Execution: ")
    st.write(results["malware"])

    st.write("Data Exfiltration: ")
    st.write(results["exfiltration"])
    

# ------------------------------------------------
# IMPACT
# ------------------------------------------------
if "impact" in st.session_state:

    st.subheader("Impact Level")

    impact = st.session_state["impact"]

    if impact == "CRITICAL":
        st.error(impact)

    elif impact == "HIGH":
        st.error(impact)

    elif impact == "MEDIUM":
        st.warning(impact)

    elif impact == "LOW":
        st.info(impact)

    else:
        st.success(impact)

# ------------------------------------------------
# RECOMMENDATIONS
# ------------------------------------------------
if "recommendations" in st.session_state:

    st.subheader("Recommended Actions")

    for recommendation in st.session_state[
        "recommendations"
    ]:
        st.success(recommendation)

# ------------------------------------------------
# KNOWLEDGE GRAPH
# ------------------------------------------------
if "evidence" in st.session_state:

    st.subheader("Attack Knowledge Graph")

    graph = AttackKnowledgeGraph()

    graph.build_graph(evidence)

    fig, ax = plt.subplots(
        figsize=(10, 7)
    )

    pos = nx.spring_layout(
        graph.graph
    )

    nx.draw(
        graph.graph,
        pos,
        with_labels=True,
        node_color="lightblue",
        node_size=1200,
        font_size=8,
        ax=ax
    )

    st.pyplot(fig)

# ------------------------------------------------
# CHATBOT
# ------------------------------------------------
st.divider()

st.subheader("SOC Assistant Chat")

if "chat_history" not in st.session_state:
    st.session_state["chat_history"] = []

user_input = st.chat_input(
    "Ask something about the incident..."
)

if user_input:

    if "evidence" not in st.session_state:

        st.warning(
            "Run simulation first."
        )

    else:

        model = RiskPredictionModel()

        engine = SOCChatEngine(
            st.session_state["evidence"]
        )

        response = engine.process_query(
            user_input,
            model
        )

        st.session_state["chat_history"].append({
            "role": "user",
            "message": user_input
        })

        st.session_state["chat_history"].append({
            "role": "assistant",
            "message": response
        })

# ------------------------------------------------
# CHAT HISTORY
# ------------------------------------------------
for chat in st.session_state["chat_history"]:

    with st.chat_message(chat["role"]):

        st.write(chat["message"])