"""Core detection modules for Keylogger Sentinel."""

from core.models import (
    Finding,
    ProcessInfo,
    ScanResult,
    Severity,
    NetworkIndicator,
    PersistenceIndicator,
    RiskBreakdown,
)
from core.scanner import ProcessScanner
from core.persistence import PersistenceScanner
from core.network import NetworkMonitor
from core.reputation import ReputationChecker
from core.scoring import RiskScoringEngine
from core.detector import KeyloggerDetector

__all__ = [
    "Finding",
    "ProcessInfo",
    "ScanResult",
    "Severity",
    "NetworkIndicator",
    "PersistenceIndicator",
    "RiskBreakdown",
    "ProcessScanner",
    "PersistenceScanner",
    "NetworkMonitor",
    "ReputationChecker",
    "RiskScoringEngine",
    "KeyloggerDetector",
]
