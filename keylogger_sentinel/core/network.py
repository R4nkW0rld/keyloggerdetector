"""Network monitor – tracks outbound connections of suspicious processes."""

from __future__ import annotations

import socket
import time
from typing import Dict, List, Set

import psutil

from core.models import NetworkIndicator


class NetworkMonitor:
    """Monitors network connections and flags suspicious outbound activity.

    Read-only: inspects psutil.net_connections() without modifying state.
    """

    # Ports commonly abused by reverse shells and C2 frameworks
    SUSPICIOUS_PORTS: Set[int] = {
        4444, 1337, 8443, 5555, 6666, 6667, 31337,
        9001, 4443, 2222, 7777, 8888, 1234, 12345,
        54321, 19191, 2323, 4242, 7070, 9999,
    }

    # Well-known local/loopback prefixes to ignore
    LOCAL_PREFIXES = ("127.", "0.0.0.0", "::1", "localhost", "")

    def __init__(self, min_connection_duration: float = 300.0) -> None:
        """
        Args:
            min_connection_duration: Connections alive longer than this
                (seconds) are flagged. Default 300s (5 minutes).
        """
        self._min_duration = min_connection_duration

    def scan(self, target_pids: Set[int] | None = None) -> Dict[int, List[NetworkIndicator]]:
        """Scan network connections and associate them with processes.

        Args:
            target_pids: If provided, only check these PIDs.

        Returns:
            Dict mapping PID -> list of NetworkIndicator.
        """
        result: Dict[int, List[NetworkIndicator]] = {}
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return result

        now = time.time()
        for conn in connections:
            pid = conn.pid
            if pid is None or pid <= 0:
                continue
            if target_pids is not None and pid not in target_pids:
                continue

            indicator = self._evaluate(conn, now)
            if indicator is not None:
                result.setdefault(pid, []).append(indicator)

        return result

    def _evaluate(self, conn: psutil._common.sconn, now: float) -> NetworkIndicator | None:
        """Evaluate a single connection for suspicious characteristics."""
        local_addr = conn.laddr.ip if conn.laddr else ""
        local_port = conn.laddr.port if conn.laddr else 0
        remote_addr = conn.raddr.ip if conn.raddr else ""
        remote_port = conn.raddr.port if conn.raddr else 0

        # Skip connections without a remote endpoint
        if not remote_addr and not remote_port:
            return None

        status = str(conn.status) if hasattr(conn, "status") else "unknown"
        proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"

        flag_reasons: List[str] = []

        # Skip well-known ports (HTTP/HTTPS) - these are almost always benign
        KNOWN_SAFE_PORTS = {80, 443, 8080, 8443, 993, 995, 587, 465, 143, 110}

        # Flag suspicious remote ports
        if remote_port in self.SUSPICIOUS_PORTS:
            flag_reasons.append(f"Suspicious port: {remote_port}")

        # Flag non-local remote connections on non-standard ports (potential exfil/C2)
        if not self._is_local_addr(remote_addr) and remote_port not in KNOWN_SAFE_PORTS:
            if remote_port in self.SUSPICIOUS_PORTS:
                flag_reasons.append("Remote connection on known-bad port")

        # Flag long-lived established TCP connections on non-standard ports
        if status.upper() == "ESTABLISHED" and proto == "tcp":
            if not self._is_local_addr(remote_addr) and remote_port not in KNOWN_SAFE_PORTS:
                flag_reasons.append("Established external TCP connection on non-standard port")

        if not flag_reasons:
            return None

        return NetworkIndicator(
            local_addr=local_addr,
            local_port=local_port,
            remote_addr=remote_addr,
            remote_port=remote_port,
            status=status,
            proto=proto,
            flagged=True,
            flag_reasons=flag_reasons,
        )

    @staticmethod
    def _is_local_addr(addr: str) -> bool:
        """Check if an address is local/loopback."""
        if not addr:
            return True
        return addr.startswith("127.") or addr.startswith("10.") or \
            addr.startswith("192.168.") or addr.startswith("172.") or \
            addr in ("::1", "localhost", "0.0.0.0") or \
            addr.startswith("fc00:") or addr.startswith("fe80:")

    def get_connection_summary(self, indicators: List[NetworkIndicator]) -> Dict[str, int]:
        """Get a summary count of flagged connection types."""
        summary: Dict[str, int] = {}
        for ind in indicators:
            for reason in ind.flag_reasons:
                summary[reason] = summary.get(reason, 0) + 1
        return summary
