"""CSV report generator."""

from __future__ import annotations

import csv
import os
from typing import Any, Dict, List

from core.models import ScanResult


def generate_csv_report(result: ScanResult, output_path: str) -> str:
    """Export scan results to a CSV file.

    Each finding becomes one row with flattened fields.

    Args:
        result: ScanResult to export.
        output_path: Destination file path.

    Returns:
        Absolute path of the written file.
    """
    headers = [
        "PID", "Name", "Executable", "Username", "Parent",
        "CPU%", "Memory MB", "Risk Score", "Severity",
        "SHA256", "Known Bad", "Reasons",
        "Network Connections", "Persistence Mechanisms",
    ]

    rows: List[Dict[str, Any]] = []
    for f in result.findings:
        net_str = "; ".join(
            [f"{n.remote_addr}:{n.remote_port} ({n.status})" for n in f.network_indicators if n.flagged]
        ) or "None"
        pers_str = "; ".join(
            [f"{p.method}: {p.entry_name}" for p in f.persistence_indicators if p.flagged]
        ) or "None"

        rows.append({
            "PID": f.process.pid,
            "Name": f.process.name,
            "Executable": f.process.exe,
            "Username": f.process.username,
            "Parent": f.process.parent_name,
            "CPU%": f.process.cpu_percent,
            "Memory MB": f.process.memory_mb,
            "Risk Score": f.risk_score,
            "Severity": f.severity.label,
            "SHA256": f.sha256,
            "Known Bad": f.known_bad_hash,
            "Reasons": " | ".join(f.reasons),
            "Network Connections": net_str,
            "Persistence Mechanisms": pers_str,
        })

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    return os.path.abspath(output_path)
