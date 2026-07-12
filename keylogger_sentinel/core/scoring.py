"""Risk scoring engine – computes weighted risk scores for findings."""

from __future__ import annotations

from typing import Dict, List

from core.models import Finding, ProcessInfo, RiskBreakdown, Severity
from core.scanner import ProcessScanner
from core.network import NetworkIndicator
from core.persistence import PersistenceIndicator


class RiskScoringEngine:
    """Assigns weighted risk scores based on detection signals.

    All weights and thresholds are configurable via the config dict.
    """

    DEFAULT_WEIGHTS: Dict[str, int] = {
        "keyword_match": 15,
        "suspicious_path": 20,
        "suspicious_parent": 10,
        "network_connection": 25,
        "registry_autostart": 30,
        "known_bad_hash": 40,
        "system_hooks": 35,
        "hidden_execution": 15,
        "persistence": 20,
    }

    def __init__(self, config: Dict | None = None) -> None:
        """Initialize with optional config overrides.

        Args:
            config: Dict with keys matching DEFAULT_WEIGHTS or
                    a 'thresholds' sub-dict for severity levels.
        """
        self.weights = dict(self.DEFAULT_WEIGHTS)
        self.thresholds = {"low": 0, "medium": 26, "high": 51, "critical": 76}
        if config:
            if "weights" in config:
                self.weights.update(config["weights"])
            if "thresholds" in config:
                self.thresholds.update(config["thresholds"])

    def score(
        self,
        proc: ProcessInfo,
        keywords: List[str] | None = None,
        paths: List[str] | None = None,
        parent_flag: str | None = None,
        network_indicators: List[NetworkIndicator] | None = None,
        persistence_indicators: List[PersistenceIndicator] | None = None,
        known_bad: bool = False,
        hidden_flags: List[str] | None = None,
        hook_flags: List[str] | None = None,
    ) -> Finding:
        """Compute the risk score for a process.

        Args:
            proc: Process metadata.
            keywords: Matched suspicious keywords.
            paths: Matched suspicious paths.
            parent_flag: Suspicious parent-child relationship.
            network_indicators: Flagged network connections.
            persistence_indicators: Flagged persistence entries.
            known_bad: Whether the hash matched a known-bad entry.
            hidden_flags: Hidden execution reasons.
            hook_flags: System hook reasons.

        Returns:
            Finding with populated risk_score, severity, and breakdown.
        """
        breakdown: List[RiskBreakdown] = []
        total = 0

        # Keyword matches
        if keywords:
            pts = self.weights["keyword_match"] * len(keywords)
            kw_str = ", ".join(keywords[:5])
            breakdown.append(RiskBreakdown(
                category="keyword_match",
                points=pts,
                reason=f"Suspicious keywords: {kw_str}",
            ))
            total += pts

        # Suspicious path
        if paths:
            pts = self.weights["suspicious_path"] * len(paths)
            path_str = ", ".join(paths[:3])
            breakdown.append(RiskBreakdown(
                category="suspicious_path",
                points=pts,
                reason=f"Suspicious path: {path_str}",
            ))
            total += pts

        # Suspicious parent
        if parent_flag:
            pts = self.weights["suspicious_parent"]
            breakdown.append(RiskBreakdown(
                category="suspicious_parent",
                points=pts,
                reason=f"Suspicious parent: {parent_flag}",
            ))
            total += pts

        # Network connections
        if network_indicators:
            flagged = [n for n in network_indicators if n.flagged]
            if flagged:
                pts = self.weights["network_connection"] * len(flagged)
                ports = [f"{n.remote_addr}:{n.remote_port}" for n in flagged[:3]]
                breakdown.append(RiskBreakdown(
                    category="network_connection",
                    points=pts,
                    reason=f"Flagged network connections: {', '.join(ports)}",
                ))
                total += pts

        # Persistence
        if persistence_indicators:
            flagged = [p for p in persistence_indicators if p.flagged]
            if flagged:
                pts = self.weights["persistence"] * len(flagged)
                methods = [p.method for p in flagged[:3]]
                breakdown.append(RiskBreakdown(
                    category="persistence",
                    points=pts,
                    reason=f"Persistence mechanisms: {', '.join(methods)}",
                ))
                total += pts

        # Known-bad hash
        if known_bad:
            pts = self.weights["known_bad_hash"]
            breakdown.append(RiskBreakdown(
                category="known_bad_hash",
                points=pts,
                reason="Executable matches known-bad hash",
            ))
            total += pts

        # System hooks
        if hook_flags:
            pts = self.weights["system_hooks"] * len(hook_flags)
            hook_str = ", ".join(hook_flags[:3])
            breakdown.append(RiskBreakdown(
                category="system_hooks",
                points=pts,
                reason=f"System hook detected: {hook_str}",
            ))
            total += pts

        # Hidden execution
        if hidden_flags:
            pts = self.weights["hidden_execution"] * len(hidden_flags)
            hidden_str = "; ".join(hidden_flags[:3])
            breakdown.append(RiskBreakdown(
                category="hidden_execution",
                points=pts,
                reason=f"Hidden execution: {hidden_str}",
            ))
            total += pts

        severity = Severity.from_score(total)

        return Finding(
            process=proc,
            risk_score=total,
            severity=severity,
            breakdown=breakdown,
            network_indicators=network_indicators or [],
            persistence_indicators=persistence_indicators or [],
            known_bad_hash=known_bad,
        )
