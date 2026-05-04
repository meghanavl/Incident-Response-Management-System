#  SOC Incident Response Decision Support System

##  Overview

This project is an AI-powered SOC (Security Operations Center) assistant that helps analysts:

* Detect attack indicators from logs
* Predict attack probabilities using Bayesian Networks
* Recommend mitigation actions based on past incidents
* Provide explanations and chatbot-based interaction

---

##  How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the application

```bash
streamlit run soc_chatbot.py
```

### 3. Open in browser

```
http://localhost:8501
```

---

## Core Features

### 1. Log Simulation & Evidence Extraction

* File: `evidence_collection/log_parser.py`
* Simulates streaming logs (login failures, emails, PowerShell, etc.)
* Detects patterns:

  * FailedLogins
  * SuspiciousEmail
  * PowerShellExec
  * BruteForcePattern
  * MalwareSequence
* Outputs structured **evidence dictionary**

---

###  2. Bayesian Risk Model

* File: `bayesian_model/risk_model.py`
* Uses **pgmpy Bayesian Network**
* Predicts:

  * BruteForceAttack
  * PhishingAttack
  * MalwareExecution

#### How it works:

* Reads historical data from `data/incidents.csv`
* Learns probabilities using Maximum Likelihood Estimation
* Updates dataset with new simulated incidents → **continuous learning**

---

### 3. Knowledge Graph

* File: `knowledge_graph/attack_graph.py`
* Visualizes relationships:

  * Indicators → Attacks → Actions
* Built using `networkx`
* Displayed via `matplotlib` in Streamlit

---

### 4. Streamlit Dashboard

* File: `soc_chatbot.py`
* Main UI:

  * Simulate incident
  * Show logs
  * Show extracted evidence
  * Show attack probabilities
  * Show impact level
  * Show recommendations
  * Show knowledge graph

#### Important:

Uses `st.session_state` to:

* Persist logs
* Persist predictions
* Prevent UI reset during chatbot interaction

---

### 5. Chatbot Engine

* File: `chatbot/soc_chat_engine.py`
* Handles:

  * User queries
  * Decision explanation
  * Attack probability responses

#### Current Logic:

* Uses Bayesian model outputs (NOT hardcoded rules)
* Supports queries like:

  * "summary"
  * "phishing"
  * "impact"
  * "why"

---

### 6. Historical Learning (IMPORTANT)

* File: `data/incidents.csv`
* Stores:

  * Evidence features
  * Attack labels

Each simulation:
→ gets saved
→ model retrains on next run
→ system improves over time

---

## Data Flow

```text
Logs → Parser → Evidence → Bayesian Model → Predictions
                                      ↓
                               Stored in CSV
                                      ↓
                           Used for future learning
```

---

## Known Limitations (Check before submission!!!)

* Chatbot still partially keyword-based (not fully semantic yet)
* Bayesian model assumes simple relationships (can be expanded)
* No real-time external log ingestion (currently simulated)
* Recommendations are rule-based (not learned yet)

---

## What You Can Still Improve (HIGH VALUE)

### Must-have (if time permits)

* [ ] Use similarity-based recommendations from past incidents (and not saying "No past incidents" as recommendation)
* [ ] Improve chatbot using embeddings

### Advanced Improvements

* [ ] Replace CSV with database (SQLite/Postgres)
* [ ] Add real log ingestion (syslog/API)
* [ ] Use time-series / sequence modeling
* [ ] Add alert prioritization

---

## Project Structure

```
Incident-Response-Management-System/
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
├── soc_chatbot.py
├── requirements.txt
└── README.md
```

---

## Example Workflow

1. Select scenario (phishing / malware / brute force)
2. Click **Simulate Security Incident**
3. System:
   * Streams logs
   * Extracts evidence
   * Predicts attack probabilities
   * Shows impact + recommendations
4. Ask chatbot:
   * “What is the attack?”
   * “Why is this happening?”
   * “What is the impact?”

---

## Key Learning Outcomes

* Bayesian Networks for probabilistic reasoning
* Feature extraction from logs
* Streamlit UI with session persistence
* Basic ML lifecycle (data → model → retrain)
* Knowledge graph visualization
* Building an AI assistant pipeline

---

## 👨‍💻 Author

Meghana V L
