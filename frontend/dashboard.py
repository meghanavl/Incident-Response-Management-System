import streamlit as st

from backend.graph.graph_engine import GraphEngine
from backend.llm.soc_chat_engine import SOCChatEngine
from backend.reporting.incident_reporter import IncidentReporter


def render_dashboard(results):

    evidence = results["evidence"]

    st.set_page_config(
        page_title="AI-Assisted SOC Incident Response Platform",
        layout="wide"
    )

    st.title(
        "AI-Assisted SOC Incident Response Platform"
    )

    st.write("""
    This platform simulates an enterprise
    Security Operations Center (SOC).
    """)

    # ----------------------------------------
    # THREAT FEED
    # ----------------------------------------

    st.header("Live SOC Threat Feed")

    logs = []

    for event in results["events"]:

        logs.append(

            f"{event.timestamp} | "
            f"USER={event.user} | "
            f"HOST={event.host} | "
            f"EVENT={event.activity}"
        )

    st.code(
        "\n".join(logs[:30]),
        language="text"
    )

    # ----------------------------------------
    # EVIDENCE
    # ----------------------------------------

    st.header("Extracted Security Evidence")

    st.json(evidence)

    # ----------------------------------------
    # THREAT SCORES
    # ----------------------------------------

    st.header("Threat Confidence Scores")

    for name, score in (
        results["scores"].items()
    ):

        st.write(f"{name}: {score}%")

        st.progress(score / 100)

    # ----------------------------------------
    # SEVERITY
    # ----------------------------------------

    st.header("Incident Severity Level")

    severity = results["severity"]

    if severity == "CRITICAL":

        st.error("CRITICAL RISK INCIDENT")

    elif severity == "HIGH":

        st.warning("HIGH RISK INCIDENT")

    else:

        st.info("MEDIUM RISK INCIDENT")

    # ----------------------------------------
    # UEBA
    # ----------------------------------------

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

    # ----------------------------------------
    # ENDPOINT RISK
    # ----------------------------------------

    st.header("Endpoint Risk Activity")

    for host in evidence["HighRiskHosts"]:

        st.warning(
            f"{host} observed in suspicious activity"
        )

    # ----------------------------------------
    # TIMELINE
    # ----------------------------------------

    st.header("Attack Timeline Reconstruction")

    for step in results["timeline"]:

        st.markdown(f"- {step}")

    # ----------------------------------------
    # KILL CHAIN
    # ----------------------------------------

    st.header("Cyber Kill Chain Analysis")

    for phase in results["kill_chain"]:

        st.success(phase)
    

    # ----------------------------------------
    # MITRE ATT&CK MAPPING
    # ----------------------------------------

    st.header("MITRE ATT&CK Technique Mapping")

    for attack in results["attack_mapping"]:

        st.error(

            f"{attack['technique']} — "
            f"{attack['name']}"
        )

        st.caption(

            f"Tactic: {attack['tactic']}"
        )

    # ----------------------------------------
    # RECOMMENDATIONS
    # ----------------------------------------

    st.header("Recommended Response Actions")

    for action in results["recommendations"]:

        st.success(action)

    # ----------------------------------------
    # GRAPH
    # ----------------------------------------

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

    # ----------------------------------------
    # GRAPH LEGEND
    # ----------------------------------------

    st.markdown("#### Graph Legend")

    col1, col2 = st.columns(2)

    with col1:

        st.markdown(
            "🔴 **Red Nodes** → Alerted / High-Risk Hosts"
        )

        st.markdown(
            "🟠 **Orange Nodes** → Lateral Movement Activity"
        )

        st.markdown(
            "🟢 **Green Nodes** → Enterprise Hosts"
        )

    with col2:

        st.markdown(
            "🔵 **Blue Nodes** → User Accounts"
        )

        st.markdown(
            "🟡 **Yellow Nodes** → Authentication Activity"
        )

        st.markdown(
            "🟣 **Purple Edges** → Attack Progression Paths"
        )
    # ----------------------------------------
    # DOWNLOAD REPORT
    # ----------------------------------------

    st.header("Incident Report Export")

    report_generator = IncidentReporter()

    report_text = report_generator.generate_report(
        results
    )

    st.download_button(

        label="Download SOC Incident Report",

        data=report_text,

        file_name="soc_incident_report.txt",

        mime="text/plain",

        use_container_width=True
    )

    # ----------------------------------------
    # AI ANALYST
    # ----------------------------------------

    st.header("SOC AI Analyst")

    user_query = st.chat_input(
        "Ask SOC Assistant"
    )

    if user_query:

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

        st.write(response)