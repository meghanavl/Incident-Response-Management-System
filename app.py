# app.py

import streamlit as st
from datetime import datetime

from evidence_collection.log_parser import LogParser
from chatbot.soc_chat_engine import SOCChatEngine
from knowledge_graph.attack_graph import AttackGraph


st.set_page_config(
    page_title="AI-Assisted SOC Incident Response Platform",
    layout="wide"
)

st.title("AI-Assisted SOC Incident Response Platform")

st.write("""
This platform simulates an enterprise Security Operations Center (SOC).

Features:
- Real-world CERT insider threat dataset
- Live SOC threat feed
- Threat evidence extraction
- UEBA analytics
- Dynamic attack correlation
- AI-powered SOC assistant
""")

st.sidebar.title("SOC Controls")

st.sidebar.success(
    "CMU CERT Insider Threat Dataset Loaded"
)

# ------------------------------------------------
# SESSION STATE
# ------------------------------------------------

if "analysis_complete" not in st.session_state:
    st.session_state.analysis_complete = False

if "messages" not in st.session_state:
    st.session_state.messages = []

# ------------------------------------------------
# RUN ANALYSIS
# ------------------------------------------------

run_analysis = st.sidebar.button(
    "Run Threat Analysis"
)

if run_analysis:

    parser = LogParser()

    st.session_state.logs = (
        parser.stream_logs()
    )

    st.session_state.evidence = (
        parser.analyze_stream()
    )

    st.session_state.parser_logs = (
        parser.logs
    )

    st.session_state.analysis_complete = True

# ------------------------------------------------
# DISPLAY ANALYSIS
# ------------------------------------------------

if st.session_state.analysis_complete:

    logs = st.session_state.logs

    evidence = st.session_state.evidence

    st.header("Live SOC Threat Feed")

    st.code(
        "\n".join(logs),
        language="text"
    )

    # --------------------------------------------
    # EVIDENCE
    # --------------------------------------------

    st.header("Extracted Security Evidence")

    st.json(evidence)

    # --------------------------------------------
    # THREAT SCORES
    # --------------------------------------------

    st.header("Threat Confidence Scores")

    suspicious_score = min(
        evidence["SuspiciousLogons"] * 2,
        100
    )

    lateral_score = min(
        evidence["LateralMovement"] * 5,
        100
    )

    credential_score = (
        80
        if evidence["CredentialAbuse"]
        else 20
    )

    st.write(
        f"Abnormal Authentication: "
        f"{suspicious_score}%"
    )

    st.progress(
        suspicious_score / 100
    )

    st.write(
        f"Lateral Movement: "
        f"{lateral_score}%"
    )

    st.progress(
        lateral_score / 100
    )

    st.write(
        f"Credential Abuse: "
        f"{credential_score}%"
    )

    st.progress(
        credential_score / 100
    )

    # --------------------------------------------
    # SEVERITY
    # --------------------------------------------

    st.header("Incident Severity Level")

    overall_score = (
        suspicious_score +
        lateral_score +
        credential_score
    ) / 3

    if overall_score >= 70:

        severity = "CRITICAL"

        st.error(
            "CRITICAL RISK INCIDENT"
        )

    elif overall_score >= 40:

        severity = "HIGH"

        st.warning(
            "HIGH RISK INCIDENT"
        )

    else:

        severity = "MEDIUM"

        st.info(
            "MEDIUM RISK INCIDENT"
        )

    # --------------------------------------------
    # UEBA
    # --------------------------------------------

    st.header(
        "User & Entity Behavior Analytics"
    )

    st.write(
        f"Unique Users Observed: "
        f"{evidence['Users']}"
    )

    st.write(
        f"Affected Hosts: "
        f"{evidence['AffectedHosts']}"
    )

    st.write(
        f"After-Hours Logins: "
        f"{evidence['AfterHoursLogins']}"
    )

    # --------------------------------------------
    # ENDPOINT RISK
    # --------------------------------------------

    st.header("Endpoint Risk Activity")

    for host in evidence["HighRiskHosts"]:

        st.warning(
            f"{host} observed in "
            f"suspicious activity"
        )

    # --------------------------------------------
    # TIMELINE
    # --------------------------------------------

    st.header("Attack Timeline Reconstruction")

    for step in evidence["AttackTimeline"]:

        st.markdown(f"- {step}")

    # --------------------------------------------
    # CYBER KILL CHAIN
    # --------------------------------------------

    st.header(
        "Cyber Kill Chain Analysis"
    )

    kill_chain = []

    if evidence["AfterHoursLogins"] > 5:

        kill_chain.append("Reconnaissance")

    if evidence["SuspiciousLogons"] > 10:

        kill_chain.append("Exploitation")

    if evidence["CredentialAbuse"]:

        kill_chain.append( "Installation")

    if evidence["LateralMovement"] > 10:

        kill_chain.append("Command & Control")

    if evidence["AffectedHosts"] > 10:

        kill_chain.append("Exfiltration")

    if not kill_chain:

        kill_chain.append(
            "No advanced attack "
            "stages detected"
        )

    for phase in kill_chain:

        st.success(phase)

    # --------------------------------------------
    # DYNAMIC RECOMMENDATIONS
    # --------------------------------------------

    st.header("Recommended Response Actions")

    actions = []

    if evidence["CredentialAbuse"]:

        actions.append(
            "Force password reset "
            "for affected users"
        )

        actions.append(
            "Review privileged "
            "account activity"
        )

    if evidence["LateralMovement"] > 10:

        actions.append(
            "Isolate suspicious "
            "endpoints from network"
        )

        actions.append(
            "Investigate lateral "
            "movement paths"
        )

    if evidence["AfterHoursLogins"] > 5:

        actions.append(
            "Review after-hours "
            "authentication activity"
        )

    if evidence["SuspiciousLogons"] > 20:

        actions.append(
            "Enable enhanced "
            "authentication monitoring"
        )

    if evidence["AffectedHosts"] > 10:

        actions.append(
            "Perform endpoint "
            "forensic investigation"
        )

    if not actions:

        actions.append(
            "Continue monitoring "
            "security telemetry"
        )

    for action in actions:

        st.success(action)

    # --------------------------------------------
    # DYNAMIC KNOWLEDGE GRAPH
    # --------------------------------------------

    st.header(
        "Attack Correlation "
        "Knowledge Graph"
    )

    graph_builder = AttackGraph(
        st.session_state.parser_logs
    )

    graph_plot = (
        graph_builder.draw_graph()
    )

    st.pyplot(graph_plot)

    # --------------------------------------------
    # INCIDENT REPORT
    # --------------------------------------------

    st.header(
        "Automated Incident Report"
    )

    report = f"""
AI-Assisted SOC Incident Report
Generated: {datetime.now()}

====================================

INCIDENT SUMMARY
----------------
Suspicious Logons:
{evidence['SuspiciousLogons']}

After Hours Activity:
{evidence['AfterHoursLogins']}

Affected Hosts:
{evidence['AffectedHosts']}

Users Observed:
{evidence['Users']}

Credential Abuse:
{evidence['CredentialAbuse']}

Lateral Movement:
{evidence['LateralMovement']}

====================================

THREAT SEVERITY
----------------
Overall Severity:
{severity}

====================================

RECOMMENDED ACTIONS
----------------
{chr(10).join([f"- {a}" for a in actions])}

====================================

AI SOC ANALYST NOTES
----------------
This report was generated automatically
using the CMU CERT Insider Threat Dataset
and AI-assisted SOC analysis engine.
"""

    st.download_button(

        label="Download Incident Report",

        data=report,

        file_name="incident_report.txt",

        mime="text/plain"
    )

    # --------------------------------------------
    # AI ANALYST
    # --------------------------------------------

    st.header("SOC AI Analyst")

    for message in (
        st.session_state.messages
    ):

        with st.chat_message(
            message["role"]
        ):

            st.write(
                message["content"]
            )

    user_query = st.chat_input(
        "Ask SOC Assistant"
    )

    if user_query:

        st.session_state.messages.append(
            {
                "role": "user",
                "content": user_query
            }
        )

        with st.chat_message("user"):

            st.write(user_query)

        engine = SOCChatEngine(
            evidence
        )

        with st.spinner(
            "Analyzing incident..."
        ):

            response = (
                engine.process_query(
                    user_query
                )
            )

        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": response
            }
        )

        with st.chat_message(
            "assistant"
        ):

            st.write(response)