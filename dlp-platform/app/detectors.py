import re
from dataclasses import dataclass
from typing import Iterable, List

@dataclass
class PatternDetector:
    name: str
    pattern: re.Pattern
    severity: str

    def finditer(self, text: str):
        for m in self.pattern.finditer(text):
            yield {
                "detector": self.name,
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "severity": self.severity,
            }

# Basic patterns (MVP)
EMAIL = PatternDetector(
    name="EMAIL",
    pattern=re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    severity="low",
)
CREDIT_CARD = PatternDetector(
    name="CREDIT_CARD",
    pattern=re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    severity="high",
)
SSN = PatternDetector(
    name="SSN",
    pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    severity="high",
)
PHONE = PatternDetector(
    name="PHONE",
    pattern=re.compile(r"\b(?:\+?\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4})\b"),
    severity="medium",
)
API_KEY = PatternDetector(
    name="API_KEY",
    pattern=re.compile(r"\b(?:sk|key|api|token)[_-]?[A-Za-z0-9]{16,}\b", re.IGNORECASE),
    severity="high",
)
IPV4 = PatternDetector(
    name="IPV4",
    pattern=re.compile(r"\b(?:(?:2[0-5]{2}|1?\d?\d)\.){3}(?:2[0-5]{2}|1?\d?\d)\b"),
    severity="low",
)
IBAN = PatternDetector(
    name="IBAN",
    pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b"),
    severity="high",
)

ALL_DETECTORS: List[PatternDetector] = [EMAIL, CREDIT_CARD, SSN, PHONE, API_KEY, IPV4, IBAN]

NAME_TO_DETECTOR = {d.name: d for d in ALL_DETECTORS}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

def filter_by_min_severity(findings: List[dict], min_severity: str) -> List[dict]:
    min_rank = SEVERITY_ORDER.get(min_severity, 0)
    return [f for f in findings if SEVERITY_ORDER.get(f["severity"], 0) >= min_rank]

def run_detectors(text: str, detector_names: List[str]) -> List[dict]:
    findings: List[dict] = []
    for name in detector_names:
        det = NAME_TO_DETECTOR.get(name)
        if not det:
            continue
        findings.extend(list(det.finditer(text)))
    return findings