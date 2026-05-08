from dataclasses import dataclass


@dataclass
class Incident:

    evidence: dict
    severity: str
    scores: dict
    timeline: list
    recommendations: list
    kill_chain: list