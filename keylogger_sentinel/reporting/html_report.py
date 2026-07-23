"""HTML report generator – produces a styled, self-contained HTML report."""

from __future__ import annotations

import html
import os
import time
from typing import Any

from core.models import ScanResult


def generate_html_report(result: ScanResult, output_path: str) -> str:
    """Export scan results to a styled HTML file.

    Args:
        result: ScanResult to export.
        output_path: Destination file path.

    Returns:
        Absolute path of the written file.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result.scan_timestamp))
    severity_colors = {
        "Low": "#2ecc71",
        "Medium": "#f39c12",
        "High": "#e74c3c",
        "Critical": "#8e44ad",
    }

    findings_html = ""
    for f in result.findings:
        color = severity_colors.get(f.severity.label, "#95a5a6")
        reasons_html = "".join(
            f"<li>{html.escape(r)}</li>" for r in f.reasons
        ) or "<li>No specific reasons</li>"

        network_html = ""
        if f.network_indicators:
            flagged = [n for n in f.network_indicators if n.flagged]
            if flagged:
                items = "".join(
                    f"<li>{html.escape(n.remote_addr)}:{n.remote_port} "
                    f"({html.escape(n.status)}) - "
                    f"{html.escape(', '.join(n.flag_reasons))}</li>"
                    for n in flagged
                )
                network_html = f"<h4>Network</h4><ul>{items}</ul>"

        persistence_html = ""
        if f.persistence_indicators:
            flagged = [p for p in f.persistence_indicators if p.flagged]
            if flagged:
                items = "".join(
                    f"<li><strong>{html.escape(p.method)}</strong>: "
                    f"{html.escape(p.entry_name)} - "
                    f"{html.escape(', '.join(p.flag_reasons))}</li>"
                    for p in flagged
                )
                persistence_html = f"<h4>Persistence</h4><ul>{items}</ul>"

        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color}; padding: 12px; margin: 12px 0; background: #f9f9f9; border-radius: 4px;">
            <h3 style="margin: 0;">
                <span style="background: {color}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em;">
                    {html.escape(f.severity.label)} ({f.risk_score})
                </span>
                {html.escape(f.process.name)} (PID {f.process.pid})
            </h3>
            <table class="details">
                <tr><td>Executable</td><td>{html.escape(f.process.exe)}</td></tr>
                <tr><td>Username</td><td>{html.escape(f.process.username)}</td></tr>
                <tr><td>Parent</td><td>{html.escape(f.process.parent_name)}</td></tr>
                <tr><td>CPU</td><td>{f.process.cpu_percent}%</td></tr>
                <tr><td>Memory</td><td>{f.process.memory_mb} MB</td></tr>
                <tr><td>SHA-256</td><td><code>{html.escape(f.sha256[:32])}...</code></td></tr>
                <tr><td>Known Bad Hash</td><td>{"YES" if f.known_bad_hash else "No"}</td></tr>
            </table>
            <h4>Risk Reasons</h4>
            <ul>{reasons_html}</ul>
            {network_html}
            {persistence_html}
        </div>
        """

    if not findings_html:
        findings_html = '<p style="text-align: center; color: #2ecc71; font-size: 1.2em;">No suspicious processes detected.</p>'

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Keylogger Detector Report - {timestamp}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #ecf0f1; color: #2c3e50; padding: 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        header {{ background: #2c3e50; color: white; padding: 20px 30px; border-radius: 6px; margin-bottom: 20px; }}
        header h1 {{ font-size: 1.6em; }}
        header p {{ opacity: 0.8; margin-top: 4px; }}
        .summary {{ display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }}
        .summary-card {{ background: white; padding: 16px 24px; border-radius: 6px;
                         box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; min-width: 120px; }}
        .summary-card .number {{ font-size: 2em; font-weight: bold; }}
        .summary-card .label {{ color: #7f8c8d; font-size: 0.85em; }}
        table.details {{ width: 100%; border-collapse: collapse; margin: 8px 0; }}
        table.details td {{ padding: 4px 8px; border-bottom: 1px solid #ddd; font-size: 0.9em; }}
        table.details td:first-child {{ font-weight: bold; width: 140px; color: #7f8c8d; }}
        code {{ background: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; word-break: break-all; }}
        footer {{ text-align: center; color: #95a5a6; margin-top: 30px; font-size: 0.85em; }}
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>Keylogger Detector Report</h1>
        <p>Scan timestamp: {timestamp} | Platform: {html.escape(result.platform)}</p>
    </header>

    <div class="summary">
        <div class="summary-card">
            <div class="number">{result.total_processes}</div>
            <div class="label">Total Processes</div>
        </div>
        <div class="summary-card">
            <div class="number">{result.scanned_processes}</div>
            <div class="label">Scanned</div>
        </div>
        <div class="summary-card" style="border-top: 3px solid #8e44ad;">
            <div class="number" style="color: #8e44ad;">{result.critical_count}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card" style="border-top: 3px solid #e74c3c;">
            <div class="number" style="color: #e74c3c;">{result.high_count}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card" style="border-top: 3px solid #f39c12;">
            <div class="number" style="color: #f39c12;">{result.medium_count}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card" style="border-top: 3px solid #2ecc71;">
            <div class="number" style="color: #2ecc71;">{result.low_count}</div>
            <div class="label">Low</div>
        </div>
        <div class="summary-card">
            <div class="number">{result.scan_duration:.1f}s</div>
            <div class="label">Duration</div>
        </div>
    </div>

    <div id="findings">
        <h2 style="margin-bottom: 12px;">Findings ({len(result.findings)})</h2>
        {findings_html}
    </div>

    <footer>
        Keylogger Detector v1.0.0 | Generated {timestamp}
    </footer>
</div>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_html)

    return os.path.abspath(output_path)
