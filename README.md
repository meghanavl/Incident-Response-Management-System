# Incident Response Decision Support System (IRDSS)

A cybersecurity-focused incident analysis platform designed to assist security analysts in identifying, investigating, and understanding suspicious user activity using log analysis, behavioral indicators, visual analytics, and LLM-assisted investigation support.

This project uses the CMU CERT Insider Threat Dataset to simulate security monitoring and incident investigation workflows commonly seen in SOC (Security Operations Center) environments.

---

# Features

## Log & Event Analysis

* Parses and processes user activity logs
* Identifies potentially suspicious events using predefined behavioral rules
* Supports filtering and exploration of security-related activity

## Risk Scoring

* Assigns a severity/risk score to users or events based on observed indicators
* Combines multiple behavioral factors such as:

  * unusual login times
  * excessive device usage
  * abnormal access patterns
  * suspicious file activity

## UEBA-Inspired Monitoring

Implements simplified User and Entity Behavior Analytics (UEBA)-style checks by highlighting deviations from expected activity patterns.

Examples include:

* after-hours access
* unusually frequent activity
* access from multiple systems
* sudden spikes in file operations

> Note: This project uses heuristic/rule-based behavioral analysis and is not a production-grade UEBA system.

## Incident Timeline Reconstruction

* Organizes suspicious events into chronological timelines
* Helps visualize how an incident progressed over time
* Assists with investigation and reporting

## Knowledge Graph Visualization

* Displays relationships between:

  * users
  * devices
  * actions
  * events
* Helps analysts understand connections between suspicious activities

## Interactive Dashboard

Built using Streamlit for:

* incident monitoring
* analytics visualization
* investigation workflows
* risk exploration

## LLM-Assisted Investigation Support

Integrates local LLMs through Ollama to:

* summarize suspicious activity
* generate investigation insights
* assist analysts during incident review

> The LLM component is used as an investigation assistant and does not autonomously detect threats.

---

# Technologies Used

* Python
* Streamlit
* Pandas
* Plotly
* NetworkX
* Ollama
* Local LLMs (Llama 3 / Phi-3 / TinyLlama)

---

# Dataset

This project uses the:

**CMU CERT Insider Threat Dataset**

The dataset simulates realistic enterprise user activity including:

* logins
* device usage
* file access
* email activity
* web activity

Dataset source:

[CERT Insider Threat Test Dataset](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099&utm_source=chatgpt.com)

---

# Project Goals

The primary goals of this project are to:

* simulate SOC-style incident investigation workflows
* explore insider threat detection concepts
* practice cybersecurity analytics and visualization
* experiment with LLM-assisted security analysis
* build a practical cybersecurity portfolio project

---

# Current Limitations

This project is intended for educational and research purposes and has several limitations:

* Detection logic is primarily heuristic/rule-based
* Does not use advanced machine learning detection models
* Not designed for production SOC deployment
* Limited real-time monitoring capabilities
* LLM responses may occasionally generate inaccurate explanations

---

# Future Improvements

Potential future enhancements include:

* MITRE ATT&CK technique mapping
* anomaly detection models
* improved behavioral baselining
* real-time event streaming
* automated alert prioritization
* stronger incident correlation logic
* analyst feedback loops

---

# Installation

## Clone the Repository

```bash
git clone <repository-url>
cd Incident-Response-Decision-Support-System
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Run Ollama (Optional for LLM Features)

Install Ollama:

[Ollama Official Website](https://ollama.com?utm_source=chatgpt.com)

Run a local model:

```bash
ollama run llama3
```

or

```bash
ollama run phi3
```

---

# Running the Application

```bash
streamlit run app.py
```

---

# Example Use Cases

* Insider threat investigation simulation
* SOC analyst workflow demonstration
* Cybersecurity academic project
* Security analytics experimentation
* Behavioral log analysis practice

---

# Disclaimer

This project is developed for educational and research purposes only.

It is not intended to replace enterprise SIEM, UEBA, EDR, or incident response platforms.
