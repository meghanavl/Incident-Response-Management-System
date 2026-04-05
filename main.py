# main.py
from evidence_collection.log_parser import LogParser
from bayesian_model.risk_model import RiskPredictionModel

def run_pipeline():
    parser = LogParser()
    logs = parser.generate_sample_logs()
    evidence = parser.analyze_logs()

    model = RiskPredictionModel()
    result = model.predict_bruteforce(evidence["FailedLogins"])

    print("Logs:", logs)
    print("Evidence:", evidence)
    print("Prediction:", result)


if __name__ == "__main__":
    run_pipeline()
