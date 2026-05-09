import streamlit as st

from backend.orchestration.incident_pipeline import IncidentPipeline

from frontend.dashboard import render_dashboard
from backend.intelligence.dataset_profiles import (
    DATASET_PROFILES
)

# ----------------------------------------
# INITIAL LOAD
# ----------------------------------------

if "results" not in st.session_state:

    pipeline = IncidentPipeline(
        "CMU_CERT"
    )

    st.session_state.results = (
        pipeline.run()
    )


# ----------------------------------------
# SIDEBAR
# ----------------------------------------

st.sidebar.title("SOC Controls")

selected_dataset = st.sidebar.selectbox(

    "Select Cybersecurity Dataset",

    list(DATASET_PROFILES.keys())
)

st.sidebar.success(
    f"{selected_dataset} Dataset Loaded"
)

st.sidebar.markdown("")

if st.sidebar.button(

    "Run Threat Analysis",

    use_container_width=True
):

    pipeline = IncidentPipeline(
        selected_dataset
    )

    st.session_state.results = (
        pipeline.run()
    )
    
# ----------------------------------------
# RENDER DASHBOARD
# ----------------------------------------

render_dashboard(
    st.session_state.results
)