import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import streamlit as st

from evidence_collection.log_parser import LogParser
from bayesian_model.risk_model import RiskPredictionModel

st.set_page_config(page_title="SOC Incident Response Assistant", layout="wide")

st.title("🔐 SOC Incident Response Decision Support System")

st.write(
    """
This AI assistant helps SOC analysts during security incidents.

Features:
- Detect attack indicators from logs
- Predict attack probability
- Recommend mitigation actions
"""
)

st.divider()

if st.button("🚨 Simulate Security Incident"):

    parser = LogParser()
    logs = parser.generate_sample_logs()

    st.subheader("📜 Generated Logs")
    for log in logs:
        st.code(log)

    evidence = parser.analyze_logs()

    st.subheader("🔍 Extracted Evidence")
    st.json(evidence)

    model = RiskPredictionModel()

    result = model.predict_bruteforce(evidence["FailedLogins"])

    st.subheader("📊 Attack Probability")

    st.write(result)

    st.subheader("🛡 Recommended SOC Actions")

    if evidence["FailedLogins"] == 1:
        st.success("Lock affected accounts and monitor authentication logs.")

    if evidence["SuspiciousEmail"] == 1:
        st.warning("Investigate phishing email and alert users.")

    if evidence["PowerShellExec"] == 1:
        st.error("Isolate the affected machine immediately.")