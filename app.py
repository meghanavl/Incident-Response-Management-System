import streamlit as st

from backend.orchestration.incident_pipeline import IncidentPipeline

from frontend.dashboard import render_dashboard


# ----------------------------------------
# INITIAL LOAD
# ----------------------------------------

if "results" not in st.session_state:

    pipeline = IncidentPipeline()

    st.session_state.results = (
        pipeline.run()
    )

# ----------------------------------------
# SIDEBAR
# ----------------------------------------

st.sidebar.title("SOC Controls")

st.sidebar.success(
    "CMU CERT Insider Threat Dataset Loaded"
)

st.sidebar.markdown("")

if st.sidebar.button(
    "Run Threat Analysis",
    use_container_width=True
):

    pipeline = IncidentPipeline()

    st.session_state.results = (
        pipeline.run()
    )

# ----------------------------------------
# RENDER DASHBOARD
# ----------------------------------------

render_dashboard(
    st.session_state.results
)