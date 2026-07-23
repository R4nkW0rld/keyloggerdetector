"""Main GUI application for Keylogger Detector."""

from __future__ import annotations

import os
import sys
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, Optional

try:
    import customtkinter as ctk

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
except ImportError:
    import tkinter as tk
    ctk = None

from core.detector import KeyloggerDetector
from core.models import Finding, ScanResult, Severity
from gui.tables import FindingTable
from gui.widgets import StatusBar, SummaryCards, DetailSidebar
from gui.dialogs import ConfirmDialog, WhitelistDialog, ExportDialog
from reporting.json_report import generate_json_report
from reporting.csv_report import generate_csv_report
from reporting.html_report import generate_html_report
from utils.config import ConfigManager
from utils.whitelist import WhitelistManager
from utils.logger import logger


class DetectorApp:
    """Main application window for Keylogger Detector.

    Manages the dashboard, scanning lifecycle, auto-refresh, and
    user interactions. All detection logic is delegated to the
    KeyloggerDetector engine.
    """

    APP_TITLE = "Keylogger Detector v1.0.0"
    APP_MIN_SIZE = (1100, 650)

    def __init__(self) -> None:
        self._config = ConfigManager("config.yaml")
        self._whitelist = WhitelistManager()
        self._whitelist.load_from_config(self._config.whitelist)
        self._detector = KeyloggerDetector(self._config.data)
        self._detector.load_whitelist(self._config.whitelist)
        self._last_result: ScanResult | None = None
        self._scanning = False
        self._auto_refresh = self._config.get("auto_refresh", True)
        self._refresh_interval = self._config.get("scan_interval_seconds", 30)
        self._refresh_timer: str | None = None

        self._build_ui()

    def _build_ui(self) -> None:
        """Construct the main window layout."""
        if ctk:
            self.root = ctk.CTk()
        else:
            self.root = tk.Tk()

        self.root.title(self.APP_TITLE)
        self.root.geometry("1200x750")
        self.root.minsize(*self.APP_MIN_SIZE)

        # Top toolbar
        self._build_toolbar()

        # Main content area
        if ctk:
            self._content = ctk.CTkFrame(self.root, fg_color="transparent")
        else:
            self._content = tk.Frame(self.root)
        self._content.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Left: summary + table
        if ctk:
            self._left = ctk.CTkFrame(self._content, fg_color="transparent")
        else:
            self._left = tk.Frame(self._content)
        self._left.pack(side="left", fill="both", expand=True)

        self._summary = SummaryCards(self._left)
        self._table = FindingTable(self._left, on_select=self._on_finding_selected)
        self._table.container.pack(fill="both", expand=True)

        # Right: detail sidebar
        self._sidebar = DetailSidebar(self._content, width=380)
        self._sidebar.frame.pack(side="right", fill="y", padx=(8, 0))

        # Status bar
        self._status = StatusBar(self.root)
        self._status.set("Ready - Click 'Start Scan' to begin analysis")

    def _build_toolbar(self) -> None:
        """Build the top toolbar with control buttons."""
        if ctk:
            toolbar = ctk.CTkFrame(self.root, height=50)
        else:
            toolbar = tk.Frame(self.root, height=50)
        toolbar.pack(fill="x", padx=8, pady=8)

        buttons = [
            ("Start Scan", self._on_scan, "#3498db"),
            ("Auto Refresh", self._on_toggle_refresh, "#2ecc71" if self._auto_refresh else "#95a5a6"),
            ("Export", self._on_export, "#9b59b6"),
            ("Whitelist", self._on_whitelist, "#f39c12"),
        ]

        for text, cmd, color in buttons:
            if ctk:
                btn = ctk.CTkButton(
                    toolbar, text=text, command=cmd, width=110, height=32,
                    fg_color=color, font=ctk.CTkFont(size=12),
                )
            else:
                btn = tk.Button(
                    toolbar, text=text, command=cmd, width=12, height=1,
                    bg=color, fg="white", font=("Arial", 10, "bold"),
                )
            btn.pack(side="left", padx=5, pady=5)

        # Scan counter
        if ctk:
            self._scan_count_label = ctk.CTkLabel(
                toolbar, text="Scans: 0",
                font=ctk.CTkFont(size=11), text_color="#7f8c8d",
            )
        else:
            self._scan_count_label = tk.Label(
                toolbar, text="Scans: 0",
                font=("Arial", 9), fg="#7f8c8d",
            )
        self._scan_count_label.pack(side="right", padx=10)

        self._scan_count = 0

    def _on_scan(self) -> None:
        """Trigger a manual scan."""
        if self._scanning:
            return
        self._scanning = True
        self._status.set("Scanning...")
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self) -> None:
        """Execute scan in a background thread."""
        try:
            result = self._detector.scan(
                progress_callback=self._on_scan_progress
            )
            self._last_result = result
            self._scan_count += 1
            self.root.after(0, self._on_scan_complete, result)
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.root.after(0, self._on_scan_error, str(e))

    def _on_scan_progress(self, scanned: int, total: int) -> None:
        """Update progress in the UI thread."""
        if total > 0:
            pct = int(scanned / total * 100)
            self.root.after(0, self._status.set, f"Scanning... {scanned}/{total} ({pct}%)")

    def _on_scan_complete(self, result: ScanResult) -> None:
        """Handle scan completion in the UI thread."""
        self._scanning = False
        self._table.update_findings(result.findings)
        self._summary.update(result)
        self._scan_count_label.configure(text=f"Scans: {self._scan_count}")

        msg = (
            f"Scan complete: {result.scanned_processes} processes scanned "
            f"in {result.scan_duration:.1f}s | "
            f"{result.critical_count} critical, {result.high_count} high, "
            f"{result.medium_count} medium, {result.low_count} low findings"
        )
        self._status.set(msg)

        # Desktop notification for critical findings
        if result.critical_count > 0 or result.high_count > 0:
            self._notify_high_risk(result)

        # Schedule next auto-refresh
        if self._auto_refresh:
            self._schedule_refresh()

    def _on_scan_error(self, error: str) -> None:
        self._scanning = False
        self._status.set(f"Scan error: {error}")

    def _on_finding_selected(self, finding: Finding | None) -> None:
        """Update detail sidebar when a finding is selected."""
        self._sidebar.show_finding(finding)

    def _on_toggle_refresh(self) -> None:
        """Toggle auto-refresh on/off."""
        self._auto_refresh = not self._auto_refresh
        self._status.set(f"Auto-refresh: {'ON' if self._auto_refresh else 'OFF'}")
        if not self._auto_refresh and self._refresh_timer:
            self.root.after_cancel(self._refresh_timer)
            self._refresh_timer = None

    def _schedule_refresh(self) -> None:
        """Schedule the next auto-refresh scan."""
        if self._refresh_timer:
            try:
                self.root.after_cancel(self._refresh_timer)
            except Exception:
                pass
        self._refresh_timer = self.root.after(
            self._refresh_interval * 1000, self._on_scan
        )

    def _on_export(self) -> None:
        """Open export dialog."""
        ExportDialog(
            self.root,
            output_dir=self._config.get("export.output_dir", "reports"),
            on_export=self._do_export,
        )

    def _do_export(self, fmt: str, output_dir: str) -> None:
        """Perform the export."""
        if self._last_result is None:
            self._status.set("No scan results to export. Run a scan first.")
            return

        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(output_dir, f"detector_report_{ts}.{fmt}")

        try:
            if fmt == "json":
                generate_json_report(self._last_result, path)
            elif fmt == "csv":
                generate_csv_report(self._last_result, path)
            elif fmt == "html":
                generate_html_report(self._last_result, path)
            else:
                self._status.set(f"Unknown format: {fmt}")
                return
            self._status.set(f"Report exported: {path}")
        except Exception as e:
            self._status.set(f"Export failed: {e}")

    def _on_whitelist(self) -> None:
        """Open whitelist dialog."""
        selected = self._table.selected
        pid = selected.process.pid if selected else 0
        name = selected.process.name if selected else ""
        WhitelistDialog(
            self.root, pid=pid, name=name,
            on_submit=self._add_to_whitelist,
        )

    def _add_to_whitelist(self, pid: int, name: str) -> None:
        """Add an entry to the whitelist."""
        if pid:
            self._whitelist.add_pid(pid)
            self._detector.set_whitelist(pids={pid})
        if name:
            self._whitelist.add_name(name)
            self._detector.set_whitelist(names={name})
        self._status.set(f"Whitelisted: PID={pid}, Name={name}")

    def _notify_high_risk(self, result: ScanResult) -> None:
        """Show a desktop notification for high-risk findings."""
        try:
            if sys.platform == "win32":
                # Windows toast notification
                import ctypes
                ctypes.windll.user32.MessageBoxW(
                    0,
                    f"Critical: {result.critical_count}\nHigh: {result.high_count}\n\n"
                    f"Open Keylogger Detector for details.",
                    "Keylogger Detector Alert",
                    0x30 | 0x1000,
                )
            elif sys.platform == "darwin":
                os.system(
                    f'osascript -e \'display notification "Critical: {result.critical_count}" '
                    f'with title "Keylogger Detector"\''
                )
            else:
                os.system(
                    f'notify-send "Keylogger Detector" '
                    f'"Critical: {result.critical_count} | High: {result.high_count}"'
                )
        except Exception:
            pass

    def run(self) -> None:
        """Start the application main loop."""
        logger.info("Keylogger Detector GUI started")
        if self._auto_refresh:
            self._schedule_refresh()
        self.root.mainloop()
