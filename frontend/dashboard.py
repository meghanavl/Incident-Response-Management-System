import streamlit as st

from backend.graph.graph_engine import GraphEngine
from backend.llm.soc_chat_engine import SOCChatEngine
from backend.reporting.incident_reporter import IncidentReporter


# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------

st.set_page_config(

    page_title="AI-Assisted SOC Incident Response Platform",

    layout="wide"
)


# ---------------------------------------------------
# DATASET PANEL
# ---------------------------------------------------

def render_dataset_panel(profile):

    st.subheader("Dataset Intelligence Profile")

    col1, col2 = st.columns(2)

    with col1:

        st.info(f"""
Dataset Name:
{profile["name"]}

Security Domain:
{profile["domain"]}

Detection Focus:
{profile["detection_focus"]}
""")

    with col2:

        st.success(f"""
Data Type:
{profile["data_type"]}

Dataset Source:
{profile["source"]}
""")

    st.markdown("### Dataset Description")

    st.write(profile["description"])

    st.markdown("### Available Features")

    st.code(
        ", ".join(profile["features"])
    )

    st.markdown("### Supported Attack Categories")

    for attack in profile["attack_types"]:

        st.markdown(f"- {attack}")


# ---------------------------------------------------
# MAIN DASHBOARD
# ---------------------------------------------------

def render_dashboard(results):

    evidence = results["evidence"]

    profile = results["dataset_profile"]

    # ---------------------------------------------------
    # TITLE
    # ---------------------------------------------------

    st.title(
        "AI-Assisted SOC Incident Response Platform"
    )

    st.write("""
This platform simulates an enterprise
Security Operations Center (SOC).
""")

    # ---------------------------------------------------
    # DATASET PROFILE
    # ---------------------------------------------------

    render_dataset_panel(profile)
    # ---------------------------------------------------
    # LIVE SOC FEED
    # ---------------------------------------------------

    st.header("Live SOC Threat Feed")

    dataset = profile["domain"]

    events = results["events"][:25]

    # ---------------------------------------------------
    # CMU CERT
    # ---------------------------------------------------

    if dataset == "Insider Threat Detection":

        for event in events:

            risk = "🟢 NORMAL"

            if event.activity.lower() == "logon":

                risk = "🟡 AUTH EVENT"

            if "after" in str(event.timestamp).lower():

                risk = "🟠 SUSPICIOUS"

            st.markdown(f"""
    <div style="
    padding:10px;
    border-radius:8px;
    background-color:#111827;
    margin-bottom:8px;
    border-left:6px solid #3b82f6;
    ">

    <b>{risk}</b><br>

    👤 USER:
    {event.user}

    💻 HOST:
    {event.host}

    🕒 TIME:
    {event.timestamp}

    ⚡ EVENT:
    {event.activity}

    </div>
    """, unsafe_allow_html=True)

    # ---------------------------------------------------
    # CIC IDS
    # ---------------------------------------------------

    elif dataset == "Network Intrusion Detection":

        for event in events:

            severity = "🟢 NORMAL TRAFFIC"

            if str(event.protocol) == "6":

                severity = "🟠 TCP ACTIVITY"

            st.markdown(f"""
    <div style="
    padding:10px;
    border-radius:8px;
    background-color:#111827;
    margin-bottom:8px;
    border-left:6px solid #ef4444;
    ">

    <b>{severity}</b><br>

    🌐 SOURCE IP:
    {event.src_ip}

    🎯 DESTINATION IP:
    {event.dst_ip}

    📡 PROTOCOL:
    {event.protocol}

    ⚡ EVENT:
    {event.activity}

    </div>
    """, unsafe_allow_html=True)

    # ---------------------------------------------------
    # PHISHING
    # ---------------------------------------------------

    elif dataset == "Email & Web Threat Detection":

        for event in events:

            label = str(event.label).lower()

            if label == "bad":

                risk = "🔴 MALICIOUS URL"

                color = "#dc2626"

            else:

                risk = "🟢 BENIGN URL"

                color = "#16a34a"

            st.markdown(f"""
    <div style="
    padding:10px;
    border-radius:8px;
    background-color:#111827;
    margin-bottom:8px;
    border-left:6px solid {color};
    ">

    <b>{risk}</b><br>

    🔗 URL:
    {event.url[:100]}

    🏷 LABEL:
    {event.label}

    ⚡ EVENT:
    {event.activity}

    </div>
    """, unsafe_allow_html=True)
    
    # ---------------------------------------------------
    # EXTRACTED SECURITY EVIDENCE
    # ---------------------------------------------------

    st.header("Extracted Security Evidence")

    dataset = profile["domain"]

    # ---------------------------------------------------
    # CMU CERT
    # ---------------------------------------------------

    if dataset == "Insider Threat Detection":

        col1, col2 = st.columns(2)

        with col1:

            st.metric(

                "Suspicious Logons",

                evidence.get(
                    "SuspiciousLogons",
                    0
                )
            )

            st.metric(

                "After-Hours Activity",

                evidence.get(
                    "AfterHoursLogins",
                    0
                )
            )

        with col2:

            st.metric(

                "Credential Abuse",

                evidence.get(
                    "CredentialAbuse",
                    0
                )
            )

            st.metric(

                "Lateral Movement",

                evidence.get(
                    "LateralMovement",
                    0
                )
            )

    # ---------------------------------------------------
    # CIC IDS
    # ---------------------------------------------------

    elif dataset == "Network Intrusion Detection":

        col1, col2 = st.columns(2)

        with col1:

            st.metric(

                "Potential DoS",

                evidence.get(
                    "PotentialDoS",
                    0
                )
            )

            st.metric(

                "Suspicious Flows",

                evidence.get(
                    "SuspiciousFlows",
                    0
                )
            )

        with col2:

            st.metric(

                "Botnet Activity",

                evidence.get(
                    "BotnetActivity",
                    0
                )
            )

            st.metric(

                "Infiltration Attempts",

                evidence.get(
                    "InfiltrationAttempts",
                    0
                )
            )

    # ---------------------------------------------------
    # PHISHING
    # ---------------------------------------------------

    elif dataset == "Email & Web Threat Detection":

        col1, col2 = st.columns(2)

        with col1:

            st.metric(

                "Malicious URLs",

                evidence.get(
                    "MaliciousURLs",
                    0
                )
            )

            st.metric(

                "Suspicious Domains",

                evidence.get(
                    "SuspiciousDomains",
                    0
                )
            )

        with col2:

            st.metric(

                "Credential Harvesting",

                evidence.get(
                    "CredentialHarvesting",
                    0
                )
            )

    # ---------------------------------------------------
    # THREAT SCORE
    # ---------------------------------------------------

    st.header("Threat Confidence Score")

    score = results["scores"]

    st.metric(

        label="SOC Threat Score",

        value=score
    )

    st.progress(

        min(score / 200, 1.0)
    )

    # ---------------------------------------------------
    # SEVERITY
    # ---------------------------------------------------

    st.header("Incident Severity Level")

    severity = results["severity"]

    if severity == "CRITICAL":

        st.error("CRITICAL RISK INCIDENT")

    elif severity == "HIGH":

        st.warning("HIGH RISK INCIDENT")

    else:

        st.info("MEDIUM RISK INCIDENT")

    # ---------------------------------------------------
    # BAYESIAN ANALYSIS
    # ---------------------------------------------------

    st.header("Bayesian Threat Confidence")

    bayes = results["bayesian_analysis"]

    confidence = bayes["probability"]

    st.metric(

        "Threat Probability",

        f"{confidence}%"
    )

    st.progress(confidence / 100)

    if confidence >= 80:

        st.error(
            bayes["label"]
        )

    elif confidence >= 60:

        st.warning(
            bayes["label"]
        )

    else:

        st.info(
            bayes["label"]
        )

    st.markdown("#### Confidence Reasoning")

    for reason in bayes["reasoning"]:

        st.markdown(f"- {reason}")

    st.caption(

        "Probabilistic threat confidence "
        "derived from correlated "
        "behavioral indicators."
    )

    # ---------------------------------------------------
    # UEBA SECTION
    # ONLY FOR CMU
    # ---------------------------------------------------

    if profile["domain"] == "Insider Threat Detection":

        st.header(
            "User & Entity Behavior Analytics"
        )

        st.write(
            f"Unique Users Observed: "
            f"{evidence.get('Users', 0)}"
        )

        st.write(
            f"Affected Hosts: "
            f"{evidence.get('AffectedHosts', 0)}"
        )

        st.write(
            f"After-Hours Logins: "
            f"{evidence.get('AfterHoursLogins', 0)}"
        )

        # ------------------------------------------------
        # ENDPOINT RISK
        # ------------------------------------------------

        st.subheader(
            "Top Risk Endpoints"
        )

        high_risk_hosts = evidence.get(
            "HighRiskHosts",
            []
        )

        if len(high_risk_hosts) == 0:

            st.success(
                "No critical endpoints identified."
            )

        else:

            top_hosts = high_risk_hosts[:5]

            for host in top_hosts:

                st.error(
                    f"{host} → HIGH RISK HOST"
                )
    # =====================================================
    # NETWORK IOC ANALYSIS
    # =====================================================

    if results["dataset_profile"]["domain"] == "Network Intrusion Detection":

        st.header(
            "Network Threat Intelligence"
        )

        iocs = results.get(
            "network_iocs",
            {}
        )

        col1, col2 = st.columns(2)

        # -----------------------------------
        # SOURCE IPS
        # -----------------------------------

        with col1:

            st.subheader(
                "Top Source IP Activity"
            )

            st.json(
                iocs.get(
                    "TopSourceIPs",
                    {}
                )
            )

        # -----------------------------------
        # DESTINATION PORTS
        # -----------------------------------

        with col2:

            st.subheader(
                "Top Targeted Ports"
            )

            st.json(
                iocs.get(
                    "TopDestinationPorts",
                    {}
                )
            )

        # -----------------------------------
        # PROTOCOLS
        # -----------------------------------

        st.subheader(
            "Protocol Distribution"
        )

        st.json(
            iocs.get(
                "ProtocolUsage",
                {}
            )
        )

        # -----------------------------------
        # ATTACK LABELS
        # -----------------------------------

        st.subheader(
            "Observed Attack Categories"
        )

        st.json(
            iocs.get(
                "AttackLabels",
                {}
            )
        )

    # ---------------------------------------------------
    # TIMELINE
    # ---------------------------------------------------

    st.header("Attack Timeline Reconstruction")

    for step in results.get(
        "timeline",
        []
    ):

        st.markdown(f"- {step}")

    # ---------------------------------------------------
    # KILL CHAIN
    # ---------------------------------------------------

    st.header("Cyber Kill Chain Analysis")

    for phase in results.get(
        "kill_chain",
        []
    ):

        st.success(phase)

    # ---------------------------------------------------
    # MITRE ATT&CK
    # ---------------------------------------------------

    st.header("MITRE ATT&CK Technique Mapping")

    if results["attack_mapping"]:

        for attack in results["attack_mapping"]:

            st.error(

                f"{attack['technique']} — "
                f"{attack['name']}"
            )

            st.caption(

                f"Tactic: {attack['tactic']}"
            )

    else:

        st.info(
            "No ATT&CK techniques mapped."
        )

    # ---------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------

    st.header("Recommended Response Actions")

    for action in results.get(
        "recommendations",
        []
    ):

        st.success(action)

    # ---------------------------------------------------
    # GRAPH
    # ---------------------------------------------------

    st.header(
        "Attack Correlation Knowledge Graph"
    )

    graph_engine = GraphEngine(

        results["events"],

        evidence
    )

    graph_plot = (
        graph_engine.draw_graph()
    )

    st.pyplot(graph_plot)

    # ---------------------------------------------------
    # GRAPH LEGEND
    # ---------------------------------------------------
    st.markdown("#### Graph Legend")

    dataset = profile["domain"]

    # =================================================
    # CMU
    # =================================================

    if dataset == "Insider Threat Detection":

        st.markdown("🔵 Users")
        st.markdown("🟢 Enterprise Hosts")
        st.markdown("🔴 High-Risk Hosts")

    # =================================================
    # CIC IDS
    # =================================================

    elif dataset == "Network Intrusion Detection":

        st.markdown("🟠 Source IPs")
        st.markdown("🟢 Destination IPs")
        st.markdown("🔴 Botnet Activity")
        st.markdown("🟣 DoS Indicators")

    # =================================================
    # PHISHING
    # =================================================

    elif dataset == "Email & Web Threat Detection":

        st.markdown("🟡 URLs / Domains")
        st.markdown("🔴 Malicious Domains")
        st.markdown("🟢 Benign Domains")
    

    # ---------------------------------------------------
    # REPORT DOWNLOAD
    # ---------------------------------------------------

    st.header("Incident Report Export")

    report_generator = IncidentReporter()

    report_text = (
        report_generator.generate_report(
            results
        )
    )

    st.download_button(

        label="Download SOC Incident Report",

        data=report_text,

        file_name="soc_incident_report.txt",

        mime="text/plain",

        use_container_width=True
    )

    # =================================================
    # SOC AI ANALYST
    # =================================================

    st.header("SOC AI Analyst")

    from backend.llm.soc_chat_engine import (
        SOCChatEngine
    )

    # ---------------------------------------------
    # CHAT ENGINE
    # ---------------------------------------------

    engine = SOCChatEngine(
        results
    )

    # ---------------------------------------------
    # CHAT HISTORY
    # ---------------------------------------------

    if "chat_history" not in st.session_state:

        st.session_state.chat_history = []

    # ---------------------------------------------
    # DISPLAY CHAT HISTORY
    # ---------------------------------------------

    for message in st.session_state.chat_history:

        with st.chat_message(

            message["role"]
        ):

            st.markdown(
                message["content"]
            )

    # ---------------------------------------------
    # USER INPUT
    # ---------------------------------------------

    prompt = st.chat_input(
        "Ask SOC Assistant"
    )

    if prompt:

        # USER MESSAGE

        st.session_state.chat_history.append({

            "role": "user",

            "content": prompt
        })

        with st.chat_message("user"):

            st.markdown(prompt)

        # AI RESPONSE

        response = engine.process_query(
            prompt
        )

        st.session_state.chat_history.append({

            "role": "assistant",

            "content": response
        })

        with st.chat_message("assistant"):

            st.markdown(response)