from dataclasses import dataclass

@dataclass
class SecurityEvent:
    timestamp: str
    user: str
    host: str
    activity: str