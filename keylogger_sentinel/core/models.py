"""Data models and typed structures for Keylogger Sentinel."""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class Severity(enum.IntEnum):
    """Risk severity levels (ordered by danger)."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_score(cls, score: int) -> "Severity":
        if score >= 76:
            return cls.CRITICAL
        elif score >= 51:
            return cls.HIGH
        elif score >= 26:
            return cls.MEDIUM
        return cls.LOW

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def color(self) -> str:
        return {
            Severity.LOW: "#2ecc71",
            Severity.MEDIUM: "#f39c12",
            Severity.HIGH: "#e74c3c",
            Severity.CRITICAL: "#8e44ad",
        }[self]


@dataclass
class RiskBreakdown:
    """Individual risk contribution with reason string."""
    category: str
    points: int
    reason: str


@dataclass
class NetworkIndicator:
    """Outbound connection info for a suspicious process."""
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    status: str = ""
    proto: str = "tcp"
    flagged: bool = False
    flag_reasons: List[str] = field(default_factory=list)


@dataclass
class PersistenceIndicator:
    """Persistence mechanism detected for a process."""
    method: str = ""
    location: str = ""
    entry_name: str = ""
    command: str = ""
    flagged: bool = False
    flag_reasons: List[str] = field(default_factory=list)


@dataclass
class ProcessInfo:
    """Comprehensive info about a single process."""
    pid: int = 0
    name: str = ""
    exe: str = ""
    cmdline: List[str] = field(default_factory=list)
    cwd: str = ""
    username: str = ""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    parent_pid: int = 0
    parent_name: str = ""
    create_time: float = 0.0
    num_threads: int = 0
    status: str = ""
    is_hidden: bool = False
    is_system: bool = False
    platform: str = ""


@dataclass
class Finding:
    """A complete detection finding for a process."""
    process: ProcessInfo = field(default_factory=ProcessInfo)
    risk_score: int = 0
    severity: Severity = Severity.LOW
    breakdown: List[RiskBreakdown] = field(default_factory=list)
    network_indicators: List[NetworkIndicator] = field(default_factory=list)
    persistence_indicators: List[PersistenceIndicator] = field(default_factory=list)
    known_bad_hash: bool = False
    sha256: str = ""
    scan_timestamp: float = field(default_factory=time.time)

    @property
    def reasons(self) -> List[str]:
        return [b.reason for b in self.breakdown if b.points > 0]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.process.pid,
            "name": self.process.name,
            "exe": self.process.exe,
            "cmdline": self.process.cmdline,
            "username": self.process.username,
            "parent": self.process.parent_name,
            "cpu_percent": self.process.cpu_percent,
            "memory_mb": self.process.memory_mb,
            "risk_score": self.risk_score,
            "severity": self.severity.label,
            "sha256": self.sha256,
            "known_bad_hash": self.known_bad_hash,
            "reasons": self.reasons,
            "breakdown": [
                {"category": b.category, "points": b.points, "reason": b.reason}
                for b in self.breakdown
            ],
            "network": [
                {
                    "remote": f"{n.remote_addr}:{n.remote_port}",
                    "local": f"{n.local_addr}:{n.local_port}",
                    "status": n.status,
                    "flagged": n.flagged,
                    "flags": n.flag_reasons,
                }
                for n in self.network_indicators
            ],
            "persistence": [
                {
                    "method": p.method,
                    "location": p.location,
                    "entry": p.entry_name,
                    "command": p.command,
                    "flagged": p.flagged,
                    "flags": p.flag_reasons,
                }
                for p in self.persistence_indicators
            ],
            "timestamp": self.scan_timestamp,
        }


@dataclass
class ScanResult:
    """Aggregated results from a full scan."""
    findings: List[Finding] = field(default_factory=list)
    total_processes: int = 0
    scanned_processes: int = 0
    scan_duration: float = 0.0
    scan_timestamp: float = field(default_factory=time.time)
    platform: str = ""
    scan_errors: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_timestamp": self.scan_timestamp,
            "platform": self.platform,
            "total_processes": self.total_processes,
            "scanned_processes": self.scanned_processes,
            "scan_duration_seconds": round(self.scan_duration, 2),
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total_findings": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.scan_errors,
        }
