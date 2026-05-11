from data_pipeline.ingestion.log_ingestor import LogIngestor

from data_pipeline.normalization.event_normalizer import (
    EventNormalizer
)

from backend.analytics.severity_engine import (
    SeverityEngine
)

from backend.analytics.timeline_engine import (
    TimelineEngine
)

from backend.analytics.recommendation_engine import (
    RecommendationEngine
)

from backend.analytics.killchain_mapper import (
    KillChainMapper
)

from backend.intelligence.attack_mapper import (
    AttackMapper
)

from backend.intelligence.bayesian_engine import (
    BayesianEngine
)

from backend.intelligence.dataset_profiles import (
    DATASET_PROFILES
)

from backend.intelligence.network_ioc_engine import (
    NetworkIOCEngine
)

from backend.evidence.cmu_evidence import (
    CMUEvidenceEngine
)

from backend.evidence.cic_evidence import (
    CICEvidenceEngine
)

from backend.evidence.phishing_evidence import (
    PhishingEvidenceEngine
)


class IncidentPipeline:

    def __init__(self, dataset_name):

        self.dataset_name = dataset_name

    def run(self):

        # -----------------------------------
        # DATASET PROFILE
        # -----------------------------------

        profile = DATASET_PROFILES[
            self.dataset_name
        ]

        # -----------------------------------
        # INGESTION
        # -----------------------------------

        ingestor = LogIngestor(

            profile["dataset_path"]
        )

        raw_logs = ingestor.fetch_logs()

        # -----------------------------------
        # NORMALIZATION
        # -----------------------------------

        normalizer = EventNormalizer()

        events = normalizer.normalize(

            raw_logs,

            self.dataset_name
        )

        # -----------------------------------
        # EVIDENCE EXTRACTION
        # -----------------------------------

        network_iocs = {}

        if self.dataset_name == "CMU_CERT":

            evidence = (

                CMUEvidenceEngine()

                .extract(events)
            )

        elif self.dataset_name == "CIC_IDS2017":

            evidence = (

                CICEvidenceEngine()

                .extract(raw_logs)
            )

            # -----------------------------------
            # NETWORK IOC EXTRACTION
            # -----------------------------------

            network_iocs = (

                NetworkIOCEngine()

                .analyze(raw_logs)
            )

        elif self.dataset_name == "PHISHING":

            evidence = (

                PhishingEvidenceEngine()

                .extract(raw_logs)
            )

        else:

            evidence = {}

        # -----------------------------------
        # BAYESIAN ANALYSIS
        # -----------------------------------

        bayesian_analysis = (

            BayesianEngine()

            .calculate_threat_probability(
                evidence
            )
        )

        # -----------------------------------
        # SEVERITY
        # -----------------------------------

        severity_data = (

            SeverityEngine().calculate(

                evidence,

                bayesian_analysis
            )
        )

        # -----------------------------------
        # TIMELINE
        # -----------------------------------

        timeline = (

            TimelineEngine().build(
                evidence
            )
        )

        # -----------------------------------
        # RECOMMENDATIONS
        # -----------------------------------

        recommendations = (

            RecommendationEngine()

            .generate(evidence)
        )

        # -----------------------------------
        # KILL CHAIN
        # -----------------------------------

        kill_chain = (

            KillChainMapper()

            .map_phases(
                evidence,
                self.dataset_name
            )
        )

        # -----------------------------------
        # MITRE ATT&CK
        # -----------------------------------

        attack_mapping = (

            AttackMapper()

            .map_attack_techniques(
                evidence,
                self.dataset_name
            )
        )

        # -----------------------------------
        # RETURN RESULTS
        # -----------------------------------

        return {

            "events": events,

            "raw_logs": raw_logs,

            "dataset_profile": profile,

            "evidence": evidence,

            "severity":
            severity_data["severity"],

            "scores":
            severity_data["scores"],

            "timeline":
            timeline,

            "recommendations":
            recommendations,

            "kill_chain":
            kill_chain,

            "attack_mapping":
            attack_mapping,

            "bayesian_analysis":
            bayesian_analysis,

            "network_iocs":
            network_iocs
        }