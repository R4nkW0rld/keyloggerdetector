"""Bottom status bar widget."""

from __future__ import annotations

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from ui.theme import Colors, Fonts


class StatusBar(QFrame):
    """Bottom status bar with system information."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(32)
        self.setObjectName("StatusBar")
        self.setStyleSheet(f"""
            QFrame#StatusBar {{
                background-color: {Colors.BG_PANEL};
                border-top: 1px solid {Colors.BORDER};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 16, 0)
        layout.setSpacing(0)

        self._status_icon = QLabel("●")
        self._status_icon.setStyleSheet(f"""
            color: {Colors.SUCCESS};
            font-size: 8px;
            background: transparent;
        """)
        layout.addWidget(self._status_icon)

        self._status_label = QLabel("  Ready")
        self._status_label.setStyleSheet(f"""
            font-family: {Fonts.FAMILY};
            font-size: 11px;
            color: {Colors.TEXT_SECONDARY};
            background: transparent;
        """)
        layout.addWidget(self._status_label)

        layout.addStretch()

        items = [
            ("last_scan", "Last Scan: Never"),
            ("engine", "Engine v1.0"),
            ("threat_db", "Threat DB: Active"),
            ("scan_time", "Scan Time: --"),
        ]

        self._info_labels: dict[str, QLabel] = {}

        for key, text in items:
            sep = QLabel("  │  ")
            sep.setStyleSheet(f"""
                color: {Colors.BORDER};
                font-size: 11px;
                background: transparent;
            """)
            layout.addWidget(sep)

            lbl = QLabel(text)
            lbl.setStyleSheet(f"""
                font-family: {Fonts.MONO};
                font-size: 10px;
                color: {Colors.TEXT_MUTED};
                background: transparent;
            """)
            layout.addWidget(lbl)
            self._info_labels[key] = lbl

    def set_status(self, text: str, is_error: bool = False) -> None:
        color = Colors.DANGER if is_error else Colors.SUCCESS
        self._status_icon.setStyleSheet(f"color: {color}; font-size: 8px; background: transparent;")
        self._status_label.setText(f"  {text}")

    def set_last_scan(self, time_str: str) -> None:
        self._info_labels["last_scan"].setText(f"Last Scan: {time_str}")

    def set_scan_time(self, duration: str) -> None:
        self._info_labels["scan_time"].setText(f"Scan Time: {duration}")

    def set_threat_db(self, status: str) -> None:
        color = Colors.SUCCESS if status == "Active" else Colors.WARNING
        self._info_labels["threat_db"].setText(f"Threat DB: {status}")
        self._info_labels["threat_db"].setStyleSheet(f"""
            font-family: {Fonts.MONO};
            font-size: 10px;
            color: {color};
            background: transparent;
        """)

    def set_scanning(self, scanning: bool) -> None:
        if scanning:
            self._status_icon.setStyleSheet(f"color: {Colors.WARNING}; font-size: 8px; background: transparent;")
        else:
            self._status_icon.setStyleSheet(f"color: {Colors.SUCCESS}; font-size: 8px; background: transparent;")
