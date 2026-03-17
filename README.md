# SOC Incident Response Decision Support System

An AI-powered system designed to assist SOC analysts during cybersecurity incidents.

---

## Overview

This project simulates an intelligent SOC assistant that:

- Detects attack indicators from logs
- Predicts attack probability using Bayesian networks
- Recommends response actions based on attack patterns
- Provides an interactive chatbot interface

---

## Features

- Real-time Attack Pattern Recognition
- AI-based Decision Support (Bayesian Model)
- Automated Evidence Collection from Logs
- Knowledge Graph for Attack Mapping
- Interactive Chatbot Interface (Streamlit)

---

## Project Structure

```

ISRAA/
│
├── main.py                         # Entry point (backend simulation)
│
├── knowledge_graph/
│   └── attack_graph.py             # Attack pattern relationships
│
├── bayesian_model/
│   └── risk_model.py               # Bayesian network for predictions
│
├── evidence_collection/
│   └── log_parser.py               # Log generation & parsing
│
├── chatbot/
│   └── soc_chatbot.py              # Streamlit dashboard
│
└── data/                           # (Optional datasets)

````

---

### Installation

1. Clone the repository

```
git clone https://github.com/your-username/incident-response-ai.git
cd incident-response-ai
````

---

2. Install dependencies

```bash
pip install pandas numpy scikit-learn networkx matplotlib streamlit pgmpy sentence-transformers
```

---

### Running the Project

- Run the Web Dashboard
```bash
streamlit run soc_chatbot.py
```

Then open:
```
http://localhost:8501
```

---

## Run Backend Simulation (Optional)

```bash
python main.py
```

---

## System Workflow

```
Logs → Evidence Extraction → Bayesian Model → Attack Prediction → Knowledge Graph → Response Recommendation
```

---

## Example Output

* Detected Indicators:

  * Failed Logins
  * Suspicious Email
  * PowerShell Execution

* Predicted Attack:

  * Brute Force Attack (80% probability)

* Recommended Actions:

  * Lock affected accounts
  * Investigate phishing email
  * Isolate host machine

---

## Techn Used

* Python
* Streamlit
* pgmpy (Bayesian Networks)
* NetworkX (Graph Modeling)
* scikit-learn
* pandas / numpy

---

## Use Case

This system helps SOC analysts:

* Quickly assess threats
* Understand attack patterns
* Take faster and more accurate response actions

---

## Future Improvements

* Real-time log ingestion (SIEM integration)
* Advanced NLP chatbot queries
* Historical incident matching
* Risk severity classification (Low / Medium / High)
* Dashboard visualizations

---
