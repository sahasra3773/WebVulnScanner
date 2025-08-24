# vulnerabilities.py
from dataclasses import dataclass

@dataclass
class Vulnerability:
    name: str
    description: str
    severity: str
    evidence: str
    location: str

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "location": self.location,
        }
