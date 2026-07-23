"""Detail panel for displaying finding information."""

from __future__ import annotations

import os

from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QWidget, QProgressBar, QApplication,
)
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QColor, QFont, QIcon

from ui.theme import Colors, Fonts, severity_color, severity_bg
from ui.icons import (
    folder_icon, copy_icon, stop_icon, check_icon,
    external_link_icon, shield_icon, cpu_icon, memory_icon,
    hash_icon, lock_icon, key_icon, eye_icon, alert_triangle_icon,
)


class DetailPanel(QFrame):
    """Right panel showing detailed information about a selected finding."""

    add_to_whitelist = Signal(object)
    terminate_process = Signal(object)
    open_folder = Signal(str)
    copy_hash = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(380)
        self.setObjectName("DetailPanel")
        self.setStyleSheet(f"""
            QFrame#DetailPanel {{
                background-color: {Colors.BG_PANEL};
                border: 1px solid {Colors.BORDER};
                border-radius: 12px;
            }}
        """)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setStyleSheet(f"""
            QScrollArea {{
                background: transparent;
                border: none;
            }}
            QScrollArea > QWidget > QWidget {{
                background: transparent;
            }}
        """)

        self._content = QWidget()
        self._content.setStyleSheet("background: transparent;")
        self._layout = QVBoxLayout(self._content)
        self._layout.setContentsMargins(16, 16, 16, 16)
        self._layout.setSpacing(12)

        self._build_placeholder()
        self._scroll.setWidget(self._content)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self._scroll)

    def _build_placeholder(self):
        self._clear_content()

        placeholder = QVBoxLayout()
        placeholder.setAlignment(Qt.AlignCenter)
        placeholder.setSpacing(12)

        icon_label = QLabel()
        icon_label.setPixmap(shield_icon(48, Colors.TEXT_MUTED).pixmap(QSize(48, 48)))
        icon_label.setAlignment(Qt.AlignCenter)
        placeholder.addWidget(icon_label)

        text = QLabel("Select a finding to view details")
        text.setAlignment(Qt.AlignCenter)
        text.setWordWrap(True)
        text.setStyleSheet(f"""
            font-family: {Fonts.FAMILY};
            font-size: 13px;
            color: {Colors.TEXT_MUTED};
            background: transparent;
            padding: 20px;
        """)
        placeholder.addWidget(text)

        sub = QLabel("Click on any process in the table\nbelow to see its full analysis")
        sub.setAlignment(Qt.AlignCenter)
        sub.setWordWrap(True)
        sub.setStyleSheet(f"""
            font-family: {Fonts.FAMILY};
            font-size: 11px;
            color: {Colors.TEXT_MUTED};
            background: transparent;
        """)
        placeholder.addWidget(sub)

        placeholder.addStretch()

        self._layout.addLayout(placeholder)

    def _clear_content(self):
        while self._layout.count():
            item = self._layout.takeAt(0)
            child_layout = item.layout()
            if child_layout is not None:
                self._clear_layout(child_layout)
                child_layout.deleteLater()
            elif item.widget():
                item.widget().deleteLater()

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            child_layout = item.layout()
            if child_layout is not None:
                self._clear_layout(child_layout)
                child_layout.deleteLater()
            elif item.widget():
                item.widget().deleteLater()

    def show_finding(self, finding) -> None:
        if finding is None:
            self._build_placeholder()
            return

        self._clear_content()
        proc = finding.process
        severity = finding.severity.label
        color = severity_color(severity)

        header = QVBoxLayout()
        header.setSpacing(8)

        badge_row = QHBoxLayout()
        badge = QLabel(f"  {severity}  ")
        badge.setStyleSheet(f"""
            background-color: {color}20;
            color: {color};
            border: 1px solid {color}40;
            border-radius: 6px;
            padding: 4px 12px;
            font-family: {Fonts.FAMILY};
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 0.5px;
        """)
        badge_row.addWidget(badge)
        badge_row.addStretch()

        score_label = QLabel(f"Risk: {finding.risk_score}")
        score_label.setStyleSheet(f"""
            color: {color};
            font-family: {Fonts.MONO};
            font-size: 13px;
            font-weight: bold;
            background: transparent;
        """)
        badge_row.addWidget(score_label)
        header.addLayout(badge_row)

        name_label = QLabel(proc.name)
        name_label.setStyleSheet(f"""
            font-family: {Fonts.FAMILY};
            font-size: 18px;
            font-weight: bold;
            color: {Colors.TEXT_PRIMARY};
            background: transparent;
        """)
        header.addWidget(name_label)

        pid_label = QLabel(f"PID {proc.pid}")
        pid_label.setStyleSheet(f"""
            font-family: {Fonts.MONO};
            font-size: 12px;
            color: {Colors.TEXT_MUTED};
            background: transparent;
        """)
        header.addWidget(pid_label)

        self._layout.addLayout(header)

        progress_frame = QFrame()
        progress_frame.setStyleSheet(f"""
            background-color: {Colors.BG_CARD};
            border-radius: 8px;
            padding: 12px;
        """)
        progress_layout = QVBoxLayout(progress_frame)
        progress_layout.setContentsMargins(12, 12, 12, 12)
        progress_layout.setSpacing(6)

        progress_title = QLabel("Risk Score")
        progress_title.setStyleSheet(f"""
            font-family: {Fonts.FAMILY};
            font-size: 11px;
            font-weight: 600;
            color: {Colors.TEXT_SECONDARY};
            background: transparent;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        """)
        progress_layout.addWidget(progress_title)

        progress_bar = QProgressBar()
        progress_bar.setRange(0, 100)
        progress_bar.setValue(min(finding.risk_score, 100))
        progress_bar.setFixedHeight(8)
        progress_bar.setTextVisible(False)
        progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {Colors.BG_INPUT};
                border: none;
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {color}, stop:1 {color}CC);
                border-radius: 4px;
            }}
        """)
        progress_layout.addWidget(progress_bar)

        score_text = QLabel(f"{finding.risk_score} / 100")
        score_text.setAlignment(Qt.AlignRight)
        score_text.setStyleSheet(f"""
            font-family: {Fonts.MONO};
            font-size: 12px;
            font-weight: bold;
            color: {color};
            background: transparent;
        """)
        progress_layout.addWidget(score_text)

        self._layout.addWidget(progress_frame)

        info_items = [
            ("PID", str(proc.pid), key_icon(14, Colors.WARNING)),
            ("Process Name", proc.name, None),
            ("Executable Path", proc.exe, folder_icon(14, Colors.TEXT_SECONDARY)),
            ("Username", proc.username, None),
            ("Parent Process", proc.parent_name, None),
            ("CPU Usage", f"{proc.cpu_percent}%", cpu_icon(14, Colors.ACCENT)),
            ("Memory Usage", f"{proc.memory_mb} MB", memory_icon(14, Colors.PURPLE)),
            ("Threads", str(proc.num_threads), None),
            ("Status", proc.status.title(), None),
            ("Platform", proc.platform.title(), None),
        ]

        info_frame = QFrame()
        info_frame.setStyleSheet(f"""
            background-color: {Colors.BG_CARD};
            border-radius: 8px;
        """)
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(12, 12, 12, 12)
        info_layout.setSpacing(0)

        for i, (label, value, icon) in enumerate(info_items):
            row = QHBoxLayout()
            row.setSpacing(8)
            row.setContentsMargins(0, 5, 0, 5)

            if icon:
                icon_lbl = QLabel()
                icon_lbl.setPixmap(icon.pixmap(QSize(14, 14)))
                icon_lbl.setFixedSize(14, 14)
                row.addWidget(icon_lbl)

            lbl = QLabel(label)
            lbl.setStyleSheet(f"""
                font-family: {Fonts.FAMILY};
                font-size: 11px;
                color: {Colors.TEXT_MUTED};
                background: transparent;
                min-width: 100px;
            """)
            row.addWidget(lbl)

            val = QLabel(value if value else "N/A")
            val.setStyleSheet(f"""
                font-family: {Fonts.MONO};
                font-size: 11px;
                color: {Colors.TEXT_PRIMARY};
                background: transparent;
            """)
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            val.setWordWrap(True)
            row.addWidget(val, 1)

            info_layout.addLayout(row)

            if i < len(info_items) - 1:
                sep = QFrame()
                sep.setFixedHeight(1)
                sep.setStyleSheet(f"background-color: {Colors.BORDER};")
                info_layout.addWidget(sep)

        self._layout.addWidget(info_frame)

        if finding.sha256:
            hash_frame = QFrame()
            hash_frame.setStyleSheet(f"""
                background-color: {Colors.BG_CARD};
                border-radius: 8px;
            """)
            hash_layout = QVBoxLayout(hash_frame)
            hash_layout.setContentsMargins(12, 12, 12, 12)
            hash_layout.setSpacing(6)

            hash_header = QHBoxLayout()
            hash_icon_lbl = QLabel()
            hash_icon_lbl.setPixmap(hash_icon(14, Colors.TEXT_SECONDARY).pixmap(QSize(14, 14)))
            hash_header.addWidget(hash_icon_lbl)
            hash_title = QLabel("SHA-256")
            hash_title.setStyleSheet(f"""
                font-family: {Fonts.FAMILY};
                font-size: 11px;
                font-weight: 600;
                color: {Colors.TEXT_SECONDARY};
                background: transparent;
            """)
            hash_header.addWidget(hash_title)
            hash_header.addStretch()

            copy_btn = QPushButton("Copy")
            copy_btn.setIcon(copy_icon(12, Colors.ACCENT))
            copy_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {Colors.ACCENT}20;
                    color: {Colors.ACCENT};
                    border: 1px solid {Colors.ACCENT}40;
                    border-radius: 4px;
                    padding: 3px 10px;
                    font-family: {Fonts.FAMILY};
                    font-size: 10px;
                    font-weight: 600;
                }}
                QPushButton:hover {{
                    background-color: {Colors.ACCENT}40;
                }}
            """)
            copy_btn.setCursor(Qt.PointingHandCursor)
            copy_btn.clicked.connect(lambda: self.copy_hash.emit(finding.sha256))
            hash_header.addWidget(copy_btn)

            hash_layout.addLayout(hash_header)

            hash_text = QLabel(finding.sha256)
            hash_text.setWordWrap(True)
            hash_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
            hash_text.setStyleSheet(f"""
                font-family: {Fonts.MONO};
                font-size: 9px;
                color: {Colors.TEXT_MUTED};
                background: transparent;
                line-height: 1.4;
            """)
            hash_layout.addWidget(hash_text)

            self._layout.addWidget(hash_frame)

        if finding.reasons:
            reasons_frame = QFrame()
            reasons_frame.setStyleSheet(f"""
                background-color: {Colors.BG_CARD};
                border-radius: 8px;
            """)
            reasons_layout = QVBoxLayout(reasons_frame)
            reasons_layout.setContentsMargins(12, 12, 12, 12)
            reasons_layout.setSpacing(6)

            reasons_title_row = QHBoxLayout()
            alert_icon = QLabel()
            alert_icon.setPixmap(alert_triangle_icon(14, Colors.WARNING).pixmap(QSize(14, 14)))
            reasons_title_row.addWidget(alert_icon)
            reasons_title = QLabel("Detection Reasons")
            reasons_title.setStyleSheet(f"""
                font-family: {Fonts.FAMILY};
                font-size: 11px;
                font-weight: 600;
                color: {Colors.TEXT_SECONDARY};
                background: transparent;
            """)
            reasons_title_row.addWidget(reasons_title)
            reasons_title_row.addStretch()
            reasons_layout.addLayout(reasons_title_row)

            for reason in finding.reasons:
                reason_row = QHBoxLayout()
                reason_row.setSpacing(8)

                dot = QLabel("•")
                dot.setStyleSheet(f"color: {color}; font-size: 10px; background: transparent;")
                reason_row.addWidget(dot)

                reason_text = QLabel(reason)
                reason_text.setWordWrap(True)
                reason_text.setStyleSheet(f"""
                    font-family: {Fonts.FAMILY};
                    font-size: 11px;
                    color: {Colors.TEXT_PRIMARY};
                    background: transparent;
                """)
                reason_row.addWidget(reason_text, 1)
                reasons_layout.addLayout(reason_row)

            self._layout.addWidget(reasons_frame)

        if finding.breakdown:
            breakdown_frame = QFrame()
            breakdown_frame.setStyleSheet(f"""
                background-color: {Colors.BG_CARD};
                border-radius: 8px;
            """)
            breakdown_layout = QVBoxLayout(breakdown_frame)
            breakdown_layout.setContentsMargins(12, 12, 12, 12)
            breakdown_layout.setSpacing(4)

            bd_title = QLabel("Risk Breakdown")
            bd_title.setStyleSheet(f"""
                font-family: {Fonts.FAMILY};
                font-size: 11px;
                font-weight: 600;
                color: {Colors.TEXT_SECONDARY};
                background: transparent;
                margin-bottom: 4px;
            """)
            breakdown_layout.addWidget(bd_title)

            for b in finding.breakdown:
                bd_row = QHBoxLayout()
                bd_row.setSpacing(8)

                pts = QLabel(f"+{b.points}")
                pts.setStyleSheet(f"""
                    font-family: {Fonts.MONO};
                    font-size: 11px;
                    font-weight: bold;
                    color: {color};
                    background: transparent;
                    min-width: 30px;
                """)
                bd_row.addWidget(pts)

                bd_reason = QLabel(b.reason)
                bd_reason.setWordWrap(True)
                bd_reason.setStyleSheet(f"""
                    font-family: {Fonts.FAMILY};
                    font-size: 11px;
                    color: {Colors.TEXT_PRIMARY};
                    background: transparent;
                """)
                bd_row.addWidget(bd_reason, 1)
                breakdown_layout.addLayout(bd_row)

            self._layout.addWidget(breakdown_frame)

        if finding.network_indicators:
            flagged = [n for n in finding.network_indicators if n.flagged]
            if flagged:
                net_frame = QFrame()
                net_frame.setStyleSheet(f"""
                    background-color: {Colors.BG_CARD};
                    border-radius: 8px;
                """)
                net_layout = QVBoxLayout(net_frame)
                net_layout.setContentsMargins(12, 12, 12, 12)
                net_layout.setSpacing(4)

                net_title = QLabel("Network Connections")
                net_title.setStyleSheet(f"""
                    font-family: {Fonts.FAMILY};
                    font-size: 11px;
                    font-weight: 600;
                    color: {Colors.TEXT_SECONDARY};
                    background: transparent;
                """)
                net_layout.addWidget(net_title)

                for n in flagged:
                    net_row = QLabel(f"{n.remote_addr}:{n.remote_port} ({n.status})")
                    net_row.setStyleSheet(f"""
                        font-family: {Fonts.MONO};
                        font-size: 10px;
                        color: {Colors.TEXT_PRIMARY};
                        background: transparent;
                    """)
                    net_layout.addWidget(net_row)
                    for r in n.flag_reasons:
                        flag_label = QLabel(f"  → {r}")
                        flag_label.setStyleSheet(f"""
                            font-family: {Fonts.FAMILY};
                            font-size: 10px;
                            color: {Colors.WARNING};
                            background: transparent;
                        """)
                        net_layout.addWidget(flag_label)

                self._layout.addWidget(net_frame)

        if finding.persistence_indicators:
            flagged = [p for p in finding.persistence_indicators if p.flagged]
            if flagged:
                pers_frame = QFrame()
                pers_frame.setStyleSheet(f"""
                    background-color: {Colors.BG_CARD};
                    border-radius: 8px;
                """)
                pers_layout = QVBoxLayout(pers_frame)
                pers_layout.setContentsMargins(12, 12, 12, 12)
                pers_layout.setSpacing(4)

                pers_title = QLabel("Persistence Mechanisms")
                pers_title.setStyleSheet(f"""
                    font-family: {Fonts.FAMILY};
                    font-size: 11px;
                    font-weight: 600;
                    color: {Colors.TEXT_SECONDARY};
                    background: transparent;
                """)
                pers_layout.addWidget(pers_title)

                for p in flagged:
                    method_label = QLabel(f"[{p.method}] {p.entry_name}")
                    method_label.setStyleSheet(f"""
                        font-family: {Fonts.MONO};
                        font-size: 10px;
                        color: {Colors.TEXT_PRIMARY};
                        background: transparent;
                    """)
                    pers_layout.addWidget(method_label)
                    for r in p.flag_reasons:
                        flag_label = QLabel(f"  → {r}")
                        flag_label.setStyleSheet(f"""
                            font-family: {Fonts.FAMILY};
                            font-size: 10px;
                            color: {Colors.DANGER};
                            background: transparent;
                        """)
                        pers_layout.addWidget(flag_label)

                self._layout.addWidget(pers_frame)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        whitelist_btn = QPushButton("  Whitelist")
        whitelist_btn.setIcon(check_icon(14, Colors.SUCCESS))
        whitelist_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Colors.SUCCESS}15;
                color: {Colors.SUCCESS};
                border: 1px solid {Colors.SUCCESS}40;
                border-radius: 8px;
                padding: 8px 16px;
                font-family: {Fonts.FAMILY};
                font-size: 12px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {Colors.SUCCESS}30;
                border-color: {Colors.SUCCESS};
            }}
        """)
        whitelist_btn.setCursor(Qt.PointingHandCursor)
        whitelist_btn.clicked.connect(lambda: self.add_to_whitelist.emit(finding))
        btn_layout.addWidget(whitelist_btn)

        terminate_btn = QPushButton("  Terminate")
        terminate_btn.setIcon(stop_icon(14, Colors.DANGER))
        terminate_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Colors.DANGER}15;
                color: {Colors.DANGER};
                border: 1px solid {Colors.DANGER}40;
                border-radius: 8px;
                padding: 8px 16px;
                font-family: {Fonts.FAMILY};
                font-size: 12px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {Colors.DANGER}30;
                border-color: {Colors.DANGER};
            }}
        """)
        terminate_btn.setCursor(Qt.PointingHandCursor)
        terminate_btn.clicked.connect(lambda: self.terminate_process.emit(finding))
        btn_layout.addWidget(terminate_btn)

        self._layout.addLayout(btn_layout)

        extra_btns = QHBoxLayout()
        extra_btns.setSpacing(8)

        if proc.exe:
            folder_btn = QPushButton("  Open Folder")
            folder_btn.setIcon(folder_icon(14, Colors.TEXT_SECONDARY))
            folder_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {Colors.BG_CARD};
                    color: {Colors.TEXT_SECONDARY};
                    border: 1px solid {Colors.BORDER};
                    border-radius: 8px;
                    padding: 8px 16px;
                    font-family: {Fonts.FAMILY};
                    font-size: 12px;
                }}
                QPushButton:hover {{
                    background-color: {Colors.BG_CARD_HOVER};
                    color: {Colors.TEXT_PRIMARY};
                }}
            """)
            folder_btn.setCursor(Qt.PointingHandCursor)
            folder_path = os.path.dirname(proc.exe) if proc.exe else ""
            folder_btn.clicked.connect(lambda: self.open_folder.emit(folder_path))
            extra_btns.addWidget(folder_btn)

        extra_btns.addStretch()
        self._layout.addLayout(extra_btns)

        self._layout.addStretch()

    def clear(self):
        self._build_placeholder()
