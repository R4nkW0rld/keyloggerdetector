"""Main application window for Keylogger Detector (PySide6)."""

from __future__ import annotations

import os
import sys
from datetime import datetime

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFrame,
    QSplitter, QApplication, QFileDialog, QMessageBox, QLabel,
    QProgressBar,
)
from PySide6.QtCore import Qt, QTimer, Signal, QThread
from PySide6.QtGui import QIcon

import psutil

from ui.theme import Colors, Fonts, APP_STYLESHEET
from ui.toolbar import Toolbar
from ui.cards import StatsRow
from ui.process_table import ProcessTable
from ui.detail_panel import DetailPanel
from ui.status_bar import StatusBar
from ui.icons import shield_icon

from core.detector import KeyloggerDetector
from core.models import ScanResult
from reporting.json_report import generate_json_report
from reporting.csv_report import generate_csv_report
from reporting.html_report import generate_html_report
from utils.config import ConfigManager
from utils.whitelist import WhitelistManager
from utils.logger import logger


class ScanWorker(QThread):
    """Background thread for running scans without blocking the UI."""

    progress = Signal(int, int)
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, detector: KeyloggerDetector):
        super().__init__()
        self._detector = detector

    def run(self):
        try:
            result = self._detector.scan(
                progress_callback=self._on_progress
            )
            self.finished.emit(result)
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.error.emit(str(e))

    def _on_progress(self, scanned: int, total: int):
        self.progress.emit(scanned, total)


class MainWindow(QMainWindow):
    """Main application window - Premium cybersecurity dashboard."""

    def __init__(self, config_path: str | None = None):
        super().__init__()
        self._config_path = config_path or "config.yaml"
        self._config = ConfigManager(self._config_path)
        self._whitelist = WhitelistManager()
        self._whitelist.load_from_config(self._config.whitelist)
        self._detector = KeyloggerDetector(self._config.data)
        self._detector.load_whitelist(self._config.whitelist)
        self._last_result: ScanResult | None = None
        self._scanning = False
        self._auto_refresh = self._config.get("auto_refresh", True)
        self._refresh_interval = self._config.get("scan_interval_seconds", 30)
        self._scan_count = 0
        self._worker: ScanWorker | None = None

        self._refresh_timer: QTimer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.timeout.connect(self._start_scan)

        self._init_ui()
        self._connect_signals()

        if self._auto_refresh:
            self._schedule_refresh()

    def _init_ui(self):
        self.setWindowTitle("Keylogger Detector v1.0.0")
        self.setMinimumSize(1200, 750)
        self.resize(1400, 850)
        self.setWindowIcon(shield_icon(32, Colors.ACCENT))
        self.setStyleSheet(APP_STYLESHEET)

        central = QWidget()
        central.setStyleSheet(f"background-color: {Colors.BG_PRIMARY};")
        self.setCentralWidget(central)

        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self._toolbar = Toolbar()
        main_layout.addWidget(self._toolbar)

        content_widget = QWidget()
        content_widget.setStyleSheet("background: transparent;")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(16, 12, 16, 8)
        content_layout.setSpacing(12)

        self._stats_row = StatsRow()
        content_layout.addWidget(self._stats_row)

        body = QSplitter(Qt.Horizontal)
        body.setStyleSheet(f"""
            QSplitter {{
                background: transparent;
            }}
            QSplitter::handle {{
                background-color: {Colors.BORDER};
                width: 1px;
                margin: 8px 4px;
            }}
        """)

        left_widget = QWidget()
        left_widget.setStyleSheet("background: transparent;")
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        self._progress_frame = QFrame()
        self._progress_frame.setFixedHeight(0)
        self._progress_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {Colors.BG_CARD};
                border-radius: 8px;
            }}
        """)
        progress_layout = QHBoxLayout(self._progress_frame)
        progress_layout.setContentsMargins(12, 4, 12, 4)
        progress_layout.setSpacing(8)

        self._progress_label = QLabel("Scanning...")
        self._progress_label.setStyleSheet(f"""
            font-family: {Fonts.FAMILY};
            font-size: 11px;
            color: {Colors.TEXT_SECONDARY};
            background: transparent;
        """)
        progress_layout.addWidget(self._progress_label)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setFixedHeight(4)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {Colors.BG_INPUT};
                border: none;
                border-radius: 2px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {Colors.ACCENT}, stop:1 {Colors.PURPLE});
                border-radius: 2px;
            }}
        """)
        progress_layout.addWidget(self._progress_bar, 1)

        left_layout.addWidget(self._progress_frame)

        self._table = ProcessTable()
        left_layout.addWidget(self._table, 1)

        body.addWidget(left_widget)

        self._detail_panel = DetailPanel()
        body.addWidget(self._detail_panel)

        body.setSizes([900, 380])
        body.setStretchFactor(0, 3)
        body.setStretchFactor(1, 1)

        content_layout.addWidget(body, 1)

        main_layout.addWidget(content_widget, 1)

        self._status_bar = StatusBar()
        main_layout.addWidget(self._status_bar)

    def _connect_signals(self):
        self._toolbar.scan_clicked.connect(self._start_scan)
        self._toolbar.auto_refresh_toggled.connect(self._toggle_auto_refresh)
        self._toolbar.export_clicked.connect(self._show_export_dialog)
        self._toolbar.whitelist_clicked.connect(self._show_whitelist_dialog)

        self._table.finding_selected.connect(self._on_finding_selected)

        self._detail_panel.add_to_whitelist.connect(self._whitelist_finding)
        self._detail_panel.terminate_process.connect(self._terminate_process)
        self._detail_panel.open_folder.connect(self._open_folder)
        self._detail_panel.copy_hash.connect(self._copy_hash)

        self._toolbar._search.textChanged.connect(self._filter_table)

    def _start_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self._toolbar.set_scanning(True)
        self._status_bar.set_scanning(True)
        self._status_bar.set_status("Scanning processes...")

        self._progress_frame.setFixedHeight(36)
        self._progress_bar.setValue(0)
        self._progress_label.setText("Initializing scan...")

        self._worker = ScanWorker(self._detector)
        self._worker.progress.connect(self._on_scan_progress)
        self._worker.finished.connect(self._on_scan_complete)
        self._worker.error.connect(self._on_scan_error)
        self._worker.start()

    def _on_scan_progress(self, scanned: int, total: int):
        if total > 0:
            pct = int(scanned / total * 100)
            self._progress_bar.setValue(pct)
            self._progress_label.setText(f"Scanning... {scanned}/{total} ({pct}%)")

    def _on_scan_complete(self, result: ScanResult):
        self._scanning = False
        self._last_result = result
        self._scan_count += 1
        self._worker = None

        self._toolbar.set_scanning(False)
        self._status_bar.set_scanning(False)

        self._progress_frame.setFixedHeight(0)

        self._stats_row.update_from_result(result)
        self._table.set_findings(result.findings)

        if self._last_finding_shown is None:
            self._detail_panel.show_finding(None)

        now = datetime.now().strftime("%H:%M:%S")
        self._status_bar.set_last_scan(now)
        self._status_bar.set_scan_time(f"{result.scan_duration:.1f}s")

        msg = (
            f"Scan complete — {result.scanned_processes} processes analyzed "
            f"in {result.scan_duration:.1f}s"
        )
        self._status_bar.set_status(msg)

        if result.critical_count > 0 or result.high_count > 0:
            self._notify_high_risk(result)

        if self._auto_refresh:
            self._schedule_refresh()

    def _on_scan_error(self, error: str):
        self._scanning = False
        self._toolbar.set_scanning(False)
        self._status_bar.set_scanning(False)
        self._progress_frame.setFixedHeight(0)
        self._status_bar.set_status(f"Scan error: {error}", is_error=True)
        self._worker = None

    def _on_finding_selected(self, finding):
        self._last_finding_shown = finding
        self._detail_panel.show_finding(finding)

    def _toggle_auto_refresh(self, enabled: bool):
        self._auto_refresh = enabled
        self._status_bar.set_status(
            f"Auto-refresh: {'ON' if enabled else 'OFF'}"
        )
        if not enabled:
            self._refresh_timer.stop()
        else:
            self._schedule_refresh()

    def _schedule_refresh(self):
        self._refresh_timer.start(self._refresh_interval * 1000)

    def _filter_table(self, text: str):
        self._table.filter_findings(text)

    def _show_export_dialog(self):
        if self._last_result is None:
            self._status_bar.set_status("No results to export. Run a scan first.", is_error=True)
            return

        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            os.path.join(
                self._config.get("export.output_dir", "reports"),
                f"detector_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            ),
            "JSON Files (*.json);;CSV Files (*.csv);;HTML Files (*.html)"
        )

        if not path:
            return

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

        try:
            if path.endswith(".json"):
                generate_json_report(self._last_result, path)
            elif path.endswith(".csv"):
                generate_csv_report(self._last_result, path)
            elif path.endswith(".html"):
                generate_html_report(self._last_result, path)
            else:
                generate_json_report(self._last_result, path)
            self._status_bar.set_status(f"Report exported: {os.path.basename(path)}")
        except Exception as e:
            self._status_bar.set_status(f"Export failed: {e}", is_error=True)

    def _show_whitelist_dialog(self):
        selected = self._table.get_selected_finding()
        pid = selected.process.pid if selected else 0
        name = selected.process.name if selected else ""

        msg = QMessageBox(self)
        msg.setWindowTitle("Add to Whitelist")
        msg.setText(f"Add to Whitelist")
        msg.setInformativeText(
            f"Whitelist this process?\n\n"
            f"PID: {pid}\nName: {name}\n\n"
            f"This process will be excluded from future scans."
        )
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg.setIcon(QMessageBox.Question)
        msg.setStyleSheet(f"""
            QMessageBox {{
                background-color: {Colors.BG_PANEL};
                color: {Colors.TEXT_PRIMARY};
            }}
            QLabel {{
                color: {Colors.TEXT_PRIMARY};
                font-family: {Fonts.FAMILY};
            }}
            QPushButton {{
                background-color: {Colors.BG_CARD};
                color: {Colors.TEXT_PRIMARY};
                border: 1px solid {Colors.BORDER};
                border-radius: 6px;
                padding: 6px 16px;
                font-family: {Fonts.FAMILY};
                min-width: 60px;
            }}
            QPushButton:hover {{
                background-color: {Colors.BG_CARD_HOVER};
            }}
        """)

        if msg.exec() == QMessageBox.Yes:
            if pid:
                self._whitelist.add_pid(pid)
                self._detector.set_whitelist(pids={pid})
            if name:
                self._whitelist.add_name(name)
                self._detector.set_whitelist(names={name})
            self._status_bar.set_status(f"Whitelisted: {name} (PID {pid})")

    def _whitelist_finding(self, finding):
        if finding is None:
            return
        pid = finding.process.pid
        name = finding.process.name
        self._whitelist.add_pid(pid)
        self._whitelist.add_name(name)
        self._detector.set_whitelist(pids={pid}, names={name})
        self._status_bar.set_status(f"Whitelisted: {name} (PID {pid})")

    def _terminate_process(self, finding):
        if finding is None:
            return

        msg = QMessageBox(self)
        msg.setWindowTitle("Terminate Process")
        msg.setText("Terminate this process?")
        msg.setInformativeText(
            f"Process: {finding.process.name}\n"
            f"PID: {finding.process.pid}\n\n"
            f"Are you sure you want to terminate this process?"
        )
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg.setIcon(QMessageBox.Warning)
        msg.setStyleSheet(f"""
            QMessageBox {{
                background-color: {Colors.BG_PANEL};
                color: {Colors.TEXT_PRIMARY};
            }}
            QLabel {{
                color: {Colors.TEXT_PRIMARY};
                font-family: {Fonts.FAMILY};
            }}
            QPushButton {{
                background-color: {Colors.BG_CARD};
                color: {Colors.TEXT_PRIMARY};
                border: 1px solid {Colors.BORDER};
                border-radius: 6px;
                padding: 6px 16px;
                font-family: {Fonts.FAMILY};
                min-width: 60px;
            }}
            QPushButton:hover {{
                background-color: {Colors.BG_CARD_HOVER};
            }}
        """)

        if msg.exec() == QMessageBox.Yes:
            try:
                proc = psutil.Process(finding.process.pid)
                proc.terminate()
                self._status_bar.set_status(f"Terminated: {finding.process.name} (PID {finding.process.pid})")
            except Exception as e:
                self._status_bar.set_status(f"Failed to terminate: {e}", is_error=True)

    def _open_folder(self, path: str):
        if not path:
            return
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception as e:
            self._status_bar.set_status(f"Failed to open folder: {e}", is_error=True)

    def _copy_hash(self, hash_str: str):
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(hash_str)
            self._status_bar.set_status("SHA-256 hash copied to clipboard")

    def _notify_high_risk(self, result: ScanResult):
        try:
            if sys.platform == "win32":
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

    def closeEvent(self, event):
        self._refresh_timer.stop()
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait(3000)
        event.accept()

    @property
    def _last_finding_shown(self):
        return getattr(self, '_last_finding', None)

    @_last_finding_shown.setter
    def _last_finding_shown(self, finding):
        self._last_finding = finding
