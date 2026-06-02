"""
Threat Intelligence & Forensics System Package
"""

__version__ = "1.0.0"
__author__ = "CyberWala-7"

from src.breach_analyzer import BreachAnalyzer
from src.credential_detector import CredentialDetector
from src.malware_detector import MalwareDetector
from src.cve_analyzer import CVEAnalyzer
from src.incident_responder import IncidentResponder

__all__ = [
    'BreachAnalyzer',
    'CredentialDetector',
    'MalwareDetector',
    'CVEAnalyzer',
    'IncidentResponder'
]