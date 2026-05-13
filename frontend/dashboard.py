import streamlit as st

from backend.graph.graph_engine import GraphEngine
from backend.llm.soc_chat_engine import SOCChatEngine
from backend.reporting.incident_reporter import IncidentReporter


# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(

    page_title="AI-Assisted SOC Incident Response Platform",

    layout="wide"
)


# =====================================================
# DATASET PANEL
# =====================================================

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


# =====================================================
# MAIN DASHBOARD
# =====================================================

def render_dashboard(results):

    profile = results["dataset_profile"]

    events = results["events"]

    dataset = events[0].dataset_type

    domain = profile["domain"]

    evidence = results["evidence"]

    # =================================================
    # TITLE
    # =================================================

    st.title(
        "AI-Assisted SOC Incident Response Platform"
    )

    st.write("""
AI-driven Security Operations Center (SOC)
for incident detection and response.
""")

    # =================================================
    # DATASET PROFILE
    # =================================================

    render_dataset_panel(profile)

    # =================================================
    # LIVE THREAT FEED
    # =================================================

    st.header("Live Threat Feed")

    events = results["events"][:15]

    severity_colors = {

        "ALERT": "#ff2e63",
        "HIGH": "#ff6b35",
        "MEDIUM": "#f7b801",
        "INFO": "#00d084"
    }

    for index, event in enumerate(events):

        # =================================================
        # CMU CERT
        # =================================================

        if dataset == "CMU_CERT":

            timestamp = event.timestamp or "UNKNOWN_TIME"

            user = event.user or "UNKNOWN_USER"

            host = event.host or "UNKNOWN_HOST"

            activity = event.activity or "UNKNOWN_ACTIVITY"

            severity = "HIGH" if "logon" in activity.lower() else "INFO"

            prefix = f"[{timestamp}]"

            message = (
                f"USER={user} | "
                f"HOST={host} | "
                f"ACTIVITY={activity}"
            )

        # =================================================
        # CIC IDS2017
        # =================================================

        elif dataset == "CIC_IDS2017":

            flow_id = f"FLOW-{index+1:03}"

            src_ip = event.src_ip or "N/A"

            dst_ip = event.dst_ip or "N/A"

            protocol = event.protocol or "UNKNOWN"

            activity = event.activity or "UNKNOWN"

            if "infiltration" in activity.lower():

                severity = "ALERT"

            elif "benign" in activity.lower():

                severity = "INFO"

            else:

                severity = "MEDIUM"

            prefix = f"[{flow_id}]"

            message = (
                f"SRC={src_ip} | "
                f"DST={dst_ip} | "
                f"PORT={protocol} | "
                f"LABEL={activity}"
            )

        # =================================================
        # PHISHING
        # =================================================

        elif dataset == "PHISHING":

            url_id = f"URL-{index+1:03}"

            url = event.url or "UNKNOWN_URL"

            label = event.label or "UNKNOWN"

            severity = "ALERT" if label.lower() == "bad" else "INFO"

            prefix = f"[{url_id}]"

            message = (
                f"URL={url[:70]} | "
                f"LABEL={label}"
            )

        # =================================================
        # FALLBACK
        # =================================================

        else:

            severity = "INFO"

            prefix = f"[EVENT-{index}]"

            message = "Unknown event format"

        color = severity_colors.get(
            severity,
            "#00d084"
        )

        st.markdown(

            f"""
    <div style="
    background-color:#07111f;
    padding:12px;
    margin-bottom:8px;
    border-radius:8px;
    font-family:monospace;
    font-size:14px;
    border-left:4px solid {color};
    ">

    <span style="color:#8b949e;">
    {prefix}
    </span>

    <span style="
    color:{color};
    font-weight:bold;
    margin-left:10px;
    ">
    {severity}
    </span>

    <span style="
    color:white;
    margin-left:18px;
    ">
    | {message}
    </span>

    </div>
    """,

            unsafe_allow_html=True
        )



    # =================================================
    # THREAT SCORE
    # =================================================

    st.header("Threat Confidence Score")

    score = min(results["scores"], 100)

    st.metric(

        label="SOC Threat Score",

        value=score
    )

    st.progress(score / 100)

    # =================================================
    # SEVERITY
    # =================================================

    st.header("Incident Severity Level")

    severity = results["severity"]

    if severity == "CRITICAL":

        st.error("CRITICAL RISK INCIDENT")

    elif severity == "HIGH":

        st.warning("HIGH RISK INCIDENT")

    else:

        st.info("MEDIUM RISK INCIDENT")


    # =================================================
    # BAYESIAN
    # =================================================
    st.header("Bayesian Threat Confidence")

    bayes = results["bayesian_analysis"]

    confidence = bayes["probability"]

    st.metric(

        "Threat Probability",

        f"{confidence}%"
    )

    st.progress(confidence / 100)

    # =================================================
    # UEBA
    # =================================================

    if dataset == "CMU_CERT":

        st.header(
            "User and Entity Behavior Analytics"
        )

        ueba = results.get(
            "ueba_results",
            {}
        )

        risk_score = ueba.get(
            "ueba_risk_score",
            0
        )

        st.metric(
            "UEBA Insider Threat Score",
            risk_score
        )

        st.progress(risk_score / 100)

        suspicious_users = ueba.get(
            "suspicious_users",
            []
        )

        if suspicious_users:

            st.subheader(
                "Suspicious User Activity"
            )

            for user in suspicious_users:

                st.error(
                    f"{user['user']} | Risk Score: {user['risk_score']}"
                )

                st.markdown(
                    f"Hosts Accessed: {user['hosts']}"
                )
                st.markdown(
                    f"Total Events: {user['events']}"
                )

                st.markdown(
                    "Detected Anomalies:"
                )

                for anomaly in user[
                    "anomalies"
                ]:

                    st.warning(anomaly)

                st.markdown("---")

        else:

            st.success(
                "No suspicious UEBA behavior detected"
            )

    # =================================================
    # CIC IDS
    # =================================================

    if domain == "Network Intrusion Detection":

        st.header(
            "Network Threat Intelligence"
        )

        iocs = results.get(
            "network_iocs",
            {}
        )

        st.subheader(
            "Observed Attack Categories"
        )

        st.json(
            iocs.get(
                "attack_categories",
                {}
            )
        )

        st.subheader(
            "Top Targeted Ports"
        )

        st.json(
            iocs.get(
                "top_ports",
                {}
            )
        )

    # =================================================
    # TIMELINE
    # =================================================

    st.header("Attack Timeline Reconstruction")

    for step in results.get(
        "timeline",
        []
    ):

        st.markdown(f"- {step}")

    # =================================================
    # KILL CHAIN
    # =================================================

    st.header("Cyber Kill Chain Analysis")

    for phase in results.get(
        "kill_chain",
        []
    ):

        st.success(phase)

    # =================================================
    # MITRE
    # =================================================

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

    # =================================================
    # RECOMMENDATIONS
    # =================================================

    st.header("Recommended Response Actions")

    for action in results.get(
        "recommendations",
        []
    ):

        st.success(action)

    # =================================================
    # GRAPH TITLE
    # =================================================

    if dataset == "CMU_CERT":

        st.header(
            "User-Host Relationship Graph"
        )

    elif dataset == "CIC_IDS2017":

        st.header(
            "Network Flow Behavior Graph"
        )

    elif dataset == "PHISHING":

        st.header(
            "Domain Reputation Graph"
        )

    # =================================================
    # GRAPH
    # =================================================

    graph_engine = GraphEngine()

    graph_plot = graph_engine.build_graph(

        results["events"],

        dataset
    )

    st.pyplot(graph_plot)

    # =================================================
    # REPORT EXPORT
    # =================================================

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

        use_container_width=True,

        key="incident_report_download"
    )

    # =================================================
    # CHATBOT
    # =================================================

    st.header("SOC AI Analyst")

    try:

        engine = SOCChatEngine(results)

    except Exception as e:

        st.error(

            f"Failed to initialize assistant: {str(e)}"
        )

        engine = None

    if "chat_history" not in st.session_state:

        st.session_state.chat_history = []

    for message in st.session_state.chat_history:

        with st.chat_message(message["role"]):

            st.markdown(message["content"])

    prompt = st.chat_input(
        "Ask SOC Assistant"
    )

    if prompt:

        st.session_state.chat_history.append({

            "role": "user",

            "content": prompt
        })

        with st.chat_message("user"):

            st.markdown(prompt)

        if engine:

            try:

                response = engine.process_query(prompt)

            except Exception as e:

                response = str(e)

        else:

            response = (
                "SOC Assistant unavailable."
            )

        st.session_state.chat_history.append({

            "role": "assistant",

            "content": response
        })

        with st.chat_message("assistant"):

            st.markdown(response)