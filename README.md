# SOC Incident Response Decision Support System

An AI-assisted SOC (Security Operations Center) platform for analyzing simulated cybersecurity incidents using Bayesian inference, evidence extraction, knowledge graphs, and a local LLM-powered chatbot.

---

# Features

- Security log simulation
- Evidence extraction from logs
- Bayesian attack probability prediction
- Impact severity analysis
- Historical incident learning
- Attack knowledge graph visualization
- AI-powered SOC chatbot using Ollama + Phi-3
- Streamlit interactive dashboard

---

# Attack Scenarios

The system can simulate:

- Brute Force Attacks
- Phishing Attacks
- Malware Execution
- Data Exfiltration
- Mixed Multi-Stage Attacks

---

# Technologies Used

- Python
- Streamlit
- pgmpy
- NetworkX
- Matplotlib
- Ollama
- Phi-3 Mini LLM

---

# Project Structure

```text
ISRAA/
│
├── app.py
│
├── bayesian_model/
│   └── risk_model.py
│
├── evidence_collection/
│   └── log_parser.py
│
├── knowledge_graph/
│   └── attack_graph.py
│
├── chatbot/
│   └── soc_chat_engine.py
│
├── data/
│   └── incidents.csv
│
├── requirements.txt
└── README.md
```

---

# Installation

## 1. Clone Repository

```bash
git clone <your-repository-url>
cd ISRAA
```

---

## 2. Install Python Dependencies

```bash
python -m pip install -r requirements.txt
```

---

## 3. Install Ollama

Download:
https://ollama.com/download

---

## 4. Download LLM Model

```bash
ollama run phi3:mini
```

This downloads the local language model used by the SOC chatbot.

---

# Run Application

Start Streamlit:

```bash
streamlit run app.py
```

---

# AI Chatbot

The chatbot can:

- Summarize incidents
- Explain attack severity
- Identify suspicious indicators
- Recommend mitigation steps
- Explain attack reasoning

Example prompts:

```text
summarize this incident
```

```text
why is this attack critical?
```

```text
what indicators suggest malware?
```

```text
recommended mitigation actions
```

---

# Bayesian Inference

The project uses Bayesian Networks to predict:

- Brute Force Attack Probability
- Phishing Attack Probability
- Malware Execution Probability
- Data Exfiltration Probability

---

# Knowledge Graph

The system visualizes relationships between:

- Attack indicators
- Attack types
- Mitigation actions

using a cybersecurity knowledge graph.

---

# Future Improvements

- Real-world SOC datasets
- SIEM integration
- Real-time log ingestion
- Multi-user analyst dashboard
- Threat intelligence integration
- Advanced LLM reasoning

---

# Author

Meghana V L