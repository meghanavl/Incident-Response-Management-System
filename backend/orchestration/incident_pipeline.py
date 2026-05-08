from data_pipeline.ingestion.log_ingestor import LogIngestor
from data_pipeline.normalization.event_normalizer import EventNormalizer

from backend.detections.auth_detector import AuthenticationDetector
from backend.detections.credential_abuse_detector import CredentialAbuseDetector
from backend.detections.lateral_movement_detector import LateralMovementDetector

from backend.analytics.severity_engine import SeverityEngine
from backend.analytics.timeline_engine import TimelineEngine
from backend.analytics.recommendation_engine import RecommendationEngine
from backend.analytics.killchain_mapper import KillChainMapper

from backend.intelligence.attack_mapper import AttackMapper


class IncidentPipeline:

    def run(self):

        # INGESTION

        ingestor = LogIngestor()

        raw_logs = ingestor.fetch_logs()

        # NORMALIZATION

        normalizer = EventNormalizer()

        events = normalizer.normalize(raw_logs)

        # DETECTIONS

        auth = AuthenticationDetector().detect(events)

        credential = (
            CredentialAbuseDetector().detect(events)
        )

        movement = (
            LateralMovementDetector().detect(events)
        )

        # MERGE EVIDENCE

        evidence = {
            **auth,
            **credential,
            **movement
        }

        evidence["Users"] = len(
            set([e.user for e in events])
        )

        evidence["AffectedHosts"] = len(
            set([e.host for e in events])
        )

        # ANALYTICS

        severity_data = (
            SeverityEngine().calculate(evidence)
        )

        timeline = (
            TimelineEngine().build(evidence)
        )

        recommendations = (
            RecommendationEngine().generate(evidence)
        )

        kill_chain = (
            KillChainMapper().map_phases(evidence)
        )

        attack_mapping = (
            AttackMapper().map_attack_techniques(
                evidence
            )
        )

        return {

            "events": events,
            "raw_logs": raw_logs,

            "evidence": evidence,

            "severity": severity_data["severity"],

            "scores": severity_data["scores"],

            "timeline": timeline,

            "recommendations": recommendations,

            "kill_chain": kill_chain,

            "attack_mapping": attack_mapping

        }