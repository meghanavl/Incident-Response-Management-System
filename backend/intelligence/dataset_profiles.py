DATASET_PROFILES = {

    "CMU_CERT": {

        "name":
        "CMU CERT Insider Threat",

        "domain":
        "Insider Threat Detection",

        "description":
        "Synthetic enterprise insider threat dataset containing employee authentication activity and suspicious behavioral telemetry.",

        "source":
        "Carnegie Mellon University CERT",

        "data_type":
        "Authentication & User Activity Logs",

        "detection_focus":
        "UEBA / Insider Threat Analytics",

        "features": [

            "date",
            "user",
            "pc",
            "activity"

        ],

        "attack_types": [

            "Credential Abuse",
            "Privilege Misuse",
            "Lateral Movement",
            "After-Hours Access"

        ],

        "dataset_path":
        "data/logon.csv"
    },

    "CIC_IDS2017": {

        "name":
        "CIC IDS2017",

        "domain":
        "Network Intrusion Detection",

        "description":
        "Network traffic dataset containing benign and malicious flow-based attack telemetry.",

        "source":
        "Canadian Institute for Cybersecurity",

        "data_type":
        "Network Flow Records",

        "detection_focus":
        "Intrusion Detection & Traffic Analysis",

        "features": [

            "Flow Duration",
            "Packet Counts",
            "Bytes",
            "Ports",
            "Protocols"

        ],

        "attack_types": [

            "DDoS",
            "Botnet",
            "Brute Force",
            "Port Scanning",
            "Infiltration"

        ],

        "dataset_path":
        "data/cic_ids2017.csv"
    },

    "PHISHING": {

        "name":
        "Phishing URL Dataset",

        "domain":
        "Email & Web Threat Detection",

        "description":
        "Dataset containing malicious and legitimate URLs for phishing detection and threat intelligence analysis.",

        "source":
        "Phishing Website Dataset",

        "data_type":
        "URL / Web Threat Intelligence",

        "detection_focus":
        "Phishing & Malicious URL Detection",

        "features": [

            "URL",
            "Label"

        ],

        "attack_types": [

            "Phishing",
            "Credential Harvesting",
            "Spoofing",
            "Malicious URLs"

        ],

        "dataset_path":
        "data/phishing.csv"
    }
}