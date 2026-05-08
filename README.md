# AI-Assisted SOC Incident Response Platform

An intelligent Security Operations Center (SOC) simulation platform built using:

- Streamlit
- Ollama LLM
- CMU CERT Insider Threat Dataset
- Dynamic Threat Analytics
- Knowledge Graph Visualization

This project simulates real-world SOC incident investigation workflows using enterprise security telemetry data.

---

# Features

## Real CERT Insider Threat Dataset

Uses the:

### CMU CERT Insider Threat Dataset (r1)

The platform processes enterprise telemetry logs including:

- User logons/logoffs
- Endpoint activity
- Host access behavior
- Authentication events
- Insider threat indicators

Dataset source:
https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247

---

# SOC Features

## Live SOC Threat Feed

Streams real log activity from the CERT dataset in SOC-style format.

Example:

```text
11/10/2010 13:53:46 | USER=DTAA/PKH0542 | HOST=PC-2052 | EVENT=Logon
```

---

## Dynamic Evidence Extraction

Automatically extracts:

- Suspicious logons
- After-hours authentication
- Credential abuse indicators
- Lateral movement indicators
- High-risk hosts
- User activity patterns

---

## Threat Confidence Scores

Calculates dynamic threat probabilities for:

- Abnormal Authentication
- Credential Abuse
- Lateral Movement

Displayed using interactive Streamlit progress bars.

---

## Incident Severity Detection

Automatically classifies incidents into:

- MEDIUM
- HIGH
- CRITICAL

based on detected threat indicators.

---

## User & Entity Behavior Analytics (UEBA)

Tracks:

- Unique users
- Endpoint activity
- Suspicious hosts
- Authentication anomalies

---

## Endpoint Risk Activity

Highlights high-risk systems dynamically identified from suspicious activity patterns.

---

## Attack Timeline Reconstruction

Builds an attack sequence timeline from detected events such as:

- After-hours logins
- Credential abuse attempts
- Lateral movement indicators

---

## Cyber Kill Chain Analysis

Maps detected attack behavior to Cyber Kill Chain phases:

- Reconnaissance
- Weaponization
- Delivery
- Exploitation
- Installation
- Command & Control
- Exfiltration

---

## Dynamic Attack Correlation Knowledge Graph

Generates a dynamic graph showing relationships between:

- Users
- Hosts
- Suspicious endpoints
- Authentication activity
- Attack movement paths

Built using:

- NetworkX
- Matplotlib

---

## AI SOC Analyst (LLM)

Integrated with:

## Ollama

Using local LLMs such as:

- phi3:mini
- tinyllama

The assistant can:

- Explain incidents
- Summarize attacks
- Recommend mitigations
- Analyze suspicious activity
- Answer SOC investigation questions

---

## Automated Incident Report

Generates downloadable SOC incident reports containing:

- Threat evidence
- Severity assessment
- Timeline reconstruction
- Risk indicators
- Recommended response actions

---

# Technologies Used

- Python
- Streamlit
- Pandas
- NetworkX
- Matplotlib
- Ollama
- CMU CERT Dataset

---

# Project Structure

```text
project/
│
├── app.py
├── requirements.txt
│
├── chatbot/
│   └── soc_chat_engine.py
│
├── evidence_collection/
│   └── log_parser.py
│
├── data/
│   └── logon.csv
│
├── knowledge_graph/
│   └── attack_graph.py
│
└── Bayesian_model/
    └── risk_model.py
```

---

# Installation

## 1. Clone Project

```bash
git clone <repo-url>
cd project
```

---

## 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

## 3. Install Ollama

Download:
https://ollama.com/download

Verify installation:

```bash
ollama --version
```

---

## 4. Pull LLM Model

Example:

```bash
ollama pull phi3:mini
```

or

```bash
ollama pull tinyllama
```

---

# Running the Project

## Step 1 — Start Ollama

Open terminal:

```bash
ollama run phi3:mini
```

Keep this terminal running.

---

## Step 2 — Run Streamlit App

Open another terminal:

```bash
streamlit run app.py
```

---

# Dataset Setup

Download:

## CERT r1 dataset

Extract:

```text
r1.tar.bz2
```

Place:

```text
logon.csv
```

inside:

```text
data/logon.csv
```

---

# Current Dynamic Features

The following are dynamically generated from live sampled dataset logs:

- Threat evidence
- Attack timeline
- Threat attribution
- UEBA metrics
- Severity scoring
- Knowledge graph
- High-risk hosts
- Recommended mitigations

---

# Hardcoded Components

Minimal static logic still exists for:

- Severity thresholds
- Cyber Kill Chain phase labels
- Some mitigation templates

Most analytics are dynamically derived from dataset behavior.

---

# Future Improvements

- Real SIEM integration
- Neo4j graph database
- MITRE ATT&CK technique mapping
- Real-time packet analysis
- Multi-agent SOC orchestration
- Threat intelligence enrichment
- PDF incident export
- Real-time alert streaming
