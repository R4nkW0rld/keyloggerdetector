"""Main detector – orchestrates all scanners and produces findings."""

from __future__ import annotations

import time
from typing import Callable, Dict, List, Set

from core.models import Finding, ScanResult, Severity
from core.scanner import ProcessScanner
from core.persistence import PersistenceScanner
from core.network import NetworkMonitor
from core.reputation import ReputationChecker
from core.scoring import RiskScoringEngine


class KeyloggerDetector:
    """Top-level orchestrator that runs all detection modules.

    This class is the public API for the detection engine. It coordinates
    process scanning, persistence checks, network monitoring, hash
    reputation, and risk scoring into a unified ScanResult.
    """

    def __init__(self, config: Dict | None = None) -> None:
        self._config = config or {}
        self.process_scanner = ProcessScanner()
        self.persistence_scanner = PersistenceScanner()
        self.network_monitor = NetworkMonitor(
            min_connection_duration=self._config.get("min_connection_duration", 300)
        )
        self.reputation_checker = ReputationChecker()
        self.scoring_engine = RiskScoringEngine(self._config)

        # Load known-bad hashes
        hash_file = self._config.get("known_bad_hashes_file", "")
        if hash_file:
            self.reputation_checker.load_hash_file(hash_file)

        # Load whitelist
        self._whitelist_pids: Set[int] = set()
        self._whitelist_names: Set[str] = set()
        self._whitelist_paths: Set[str] = set()

    def set_whitelist(
        self,
        pids: Set[int] | None = None,
        names: Set[str] | None = None,
        paths: Set[str] | None = None,
    ) -> None:
        """Set whitelisted PIDs, names, or paths to exclude from findings."""
        if pids:
            self._whitelist_pids = pids
        if names:
            self._whitelist_names = {n.lower() for n in names}
        if paths:
            self._whitelist_paths = {p.lower() for p in paths}

    def load_whitelist(self, wl_config: Dict) -> None:
        """Load whitelist from config dict."""
        self._whitelist_pids = set(wl_config.get("pids", []))
        self._whitelist_names = {n.lower() for n in wl_config.get("names", [])}
        self._whitelist_paths = {p.lower() for p in wl_config.get("paths", [])}

    def scan(self, progress_callback: Callable[[int, int], None] | None = None) -> ScanResult:
        """Run a full scan and return aggregated results.

        Args:
            progress_callback: Optional callback(scanned, total) for progress.

        Returns:
            ScanResult with all findings.
        """
        start_time = time.time()
        result = ScanResult(platform=self.process_scanner._platform)

        # Step 1: Enumerate processes
        try:
            processes = self.process_scanner.scan()
        except Exception as e:
            result.scan_errors.append(f"Process enumeration failed: {e}")
            return result

        result.total_processes = len(processes)

        # Build PID set for network correlation
        pid_set = {p.pid for p in processes}

        # Step 2: Network scan (once for all processes)
        try:
            all_network = self.network_monitor.scan(target_pids=pid_set)
        except Exception as e:
            result.scan_errors.append(f"Network scan failed: {e}")
            all_network = {}

        # Step 3: Persistence scan (once per platform)
        try:
            persistence = self.persistence_scanner.scan()
        except Exception as e:
            result.scan_errors.append(f"Persistence scan failed: {e}")
            persistence = []

        # Step 4: Score each process
        scanned = 0
        for proc in processes:
            if progress_callback:
                progress_callback(scanned, len(processes))

            # Skip whitelisted
            if self._is_whitelisted(proc):
                continue

            # Skip low-value system processes (unless they look suspicious)
            if proc.is_system and not self._has_any_signals(proc):
                scanned += 1
                continue

            # Gather signals
            keywords = ProcessScanner.has_suspicious_keywords(proc)
            paths = ProcessScanner.has_suspicious_path(proc)
            parent = ProcessScanner.has_suspicious_parent(proc)
            hidden = ProcessScanner.has_hidden_execution(proc)
            hooks = ProcessScanner.has_system_hooks(proc)

            network = all_network.get(proc.pid, [])
            known_bad, sha256 = self.reputation_checker.check(proc)

            # Find persistence entries related to this process
            proc_persistence = self._match_persistence(proc, persistence)

            # Only score if there are any flagged signals
            flagged_persistence = [p for p in proc_persistence if p.flagged]
            if any([keywords, paths, parent, hidden, hooks,
                    network, known_bad, flagged_persistence]):
                finding = self.scoring_engine.score(
                    proc=proc,
                    keywords=keywords,
                    paths=paths,
                    parent_flag=parent,
                    network_indicators=network,
                    persistence_indicators=proc_persistence,
                    known_bad=known_bad,
                    hidden_flags=hidden,
                    hook_flags=hooks,
                )
                finding.sha256 = sha256
                result.findings.append(finding)

            scanned += 1

        # Sort findings by risk score descending
        result.findings.sort(key=lambda f: f.risk_score, reverse=True)
        result.scanned_processes = scanned
        result.scan_duration = time.time() - start_time

        if progress_callback:
            progress_callback(scanned, len(processes))

        return result

    def _is_whitelisted(self, proc: "ProcessInfo") -> bool:
        """Check if a process matches any whitelist entry."""
        if proc.pid in self._whitelist_pids:
            return True
        if proc.name.lower() in self._whitelist_names:
            return True
        if proc.exe.lower() in self._whitelist_paths:
            return True
        return False

    def _has_any_signals(self, proc: "ProcessInfo") -> bool:
        """Quick check if a system process has any suspicious signals."""
        return bool(
            ProcessScanner.has_suspicious_keywords(proc) or
            ProcessScanner.has_suspicious_path(proc) or
            ProcessScanner.has_hidden_execution(proc) or
            ProcessScanner.has_system_hooks(proc)
        )

    def _match_persistence(
        self, proc: "ProcessInfo", persistence: list
    ) -> list:
        """Match persistence entries that reference this process."""
        matched = []
        proc_exe = proc.exe.lower() if proc.exe else ""
        proc_name = proc.name.lower()
        for p in persistence:
            cmd = p.command.lower()
            if proc_exe and proc_exe in cmd:
                matched.append(p)
            elif proc_name and proc_name in cmd:
                matched.append(p)
        return matched
