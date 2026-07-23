"""Top toolbar for Keylogger Detector."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QLineEdit,
)
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QColor, QFont, QIcon

from ui.theme import Colors, Fonts
from ui.icons import (
    shield_icon, search_icon, play_icon, refresh_icon,
    download_icon, check_icon, settings_icon, bell_icon, user_icon,
)


class Toolbar(QFrame):
    """Premium top toolbar with search, actions, and branding."""

    scan_clicked = Signal()
    auto_refresh_toggled = Signal(bool)
    export_clicked = Signal()
    whitelist_clicked = Signal()
    settings_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(60)
        self.setObjectName("Toolbar")
        self.setStyleSheet(f"""
            QFrame#Toolbar {{
                background-color: {Colors.BG_PANEL};
                border-bottom: 1px solid {Colors.BORDER};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(16)

        brand = QHBoxLayout()
        brand.setSpacing(10)

        shield = QLabel()
        shield.setPixmap(shield_icon(24, Colors.ACCENT).pixmap(QSize(24, 24)))
        shield.setFixedSize(24, 24)
        brand.addWidget(shield)

        title = QLabel("Keylogger Detector")
        title.setStyleSheet(f"""
            font-family: {Fonts.FAMILY};
            font-size: 16px;
            font-weight: 700;
            color: {Colors.TEXT_PRIMARY};
            background: transparent;
            letter-spacing: -0.3px;
        """)
        brand.addWidget(title)

        version = QLabel("v1.0")
        version.setStyleSheet(f"""
            font-family: {Fonts.MONO};
            font-size: 10px;
            color: {Colors.TEXT_MUTED};
            background-color: {Colors.BG_CARD};
            border: 1px solid {Colors.BORDER};
            border-radius: 4px;
            padding: 2px 6px;
        """)
        brand.addWidget(version)

        layout.addLayout(brand)

        layout.addStretch()

        search_frame = QFrame()
        search_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {Colors.BG_INPUT};
                border: 1px solid {Colors.BORDER};
                border-radius: 8px;
            }}
            QFrame:focus-within {{
                border-color: {Colors.ACCENT};
            }}
        """)
        search_layout = QHBoxLayout(search_frame)
        search_layout.setContentsMargins(10, 0, 10, 0)
        search_layout.setSpacing(6)

        search_icon_lbl = QLabel()
        search_icon_lbl.setPixmap(search_icon(16, Colors.TEXT_MUTED).pixmap(QSize(16, 16)))
        search_icon_lbl.setFixedSize(16, 16)
        search_layout.addWidget(search_icon_lbl)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search processes...")
        self._search.setFixedWidth(200)
        self._search.setStyleSheet(f"""
            QLineEdit {{
                background: transparent;
                border: none;
                color: {Colors.TEXT_PRIMARY};
                font-family: {Fonts.FAMILY};
                font-size: 12px;
                padding: 6px 0;
            }}
            QLineEdit::placeholder {{
                color: {Colors.TEXT_MUTED};
            }}
        """)
        search_layout.addWidget(self._search)

        layout.addWidget(search_frame)

        layout.addSpacing(4)

        self._scan_btn = self._make_action_button(
            "  Start Scan", Colors.ACCENT, Colors.ACCENT_HOVER
        )
        self._scan_btn.setIcon(play_icon(14, Colors.TEXT_PRIMARY))
        self._scan_btn.clicked.connect(self.scan_clicked.emit)
        layout.addWidget(self._scan_btn)

        self._auto_btn = self._make_action_button(
            "  Auto Refresh", Colors.SUCCESS, "#16A34A"
        )
        self._auto_btn.setIcon(refresh_icon(14, Colors.TEXT_PRIMARY))
        self._auto_btn.setCheckable(True)
        self._auto_btn.setChecked(True)
        self._auto_btn.clicked.connect(lambda checked: self.auto_refresh_toggled.emit(checked))
        layout.addWidget(self._auto_btn)

        self._export_btn = self._make_action_button(
            "  Export", Colors.PURPLE, "#7C3AED"
        )
        self._export_btn.setIcon(download_icon(14, Colors.TEXT_PRIMARY))
        self._export_btn.clicked.connect(self.export_clicked.emit)
        layout.addWidget(self._export_btn)

        self._wl_btn = self._make_action_button(
            "  Whitelist", Colors.WARNING, "#D97706"
        )
        self._wl_btn.setIcon(check_icon(14, Colors.TEXT_PRIMARY))
        self._wl_btn.clicked.connect(self.whitelist_clicked.emit)
        layout.addWidget(self._wl_btn)

        layout.addSpacing(8)

        sep = QFrame()
        sep.setFixedWidth(1)
        sep.setFixedHeight(24)
        sep.setStyleSheet(f"background-color: {Colors.BORDER};")
        layout.addWidget(sep)

        bell = QPushButton()
        bell.setIcon(bell_icon(18, Colors.TEXT_SECONDARY))
        bell.setFixedSize(36, 36)
        bell.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: none;
                border-radius: 8px;
            }}
            QPushButton:hover {{
                background-color: {Colors.BG_CARD};
            }}
        """)
        bell.setCursor(Qt.PointingHandCursor)
        layout.addWidget(bell)

        settings = QPushButton()
        settings.setIcon(settings_icon(18, Colors.TEXT_SECONDARY))
        settings.setFixedSize(36, 36)
        settings.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: none;
                border-radius: 8px;
            }}
            QPushButton:hover {{
                background-color: {Colors.BG_CARD};
            }}
        """)
        settings.setCursor(Qt.PointingHandCursor)
        settings.clicked.connect(self.settings_clicked.emit)
        layout.addWidget(settings)

        user = QPushButton()
        user.setIcon(user_icon(18, Colors.TEXT_SECONDARY))
        user.setFixedSize(36, 36)
        user.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: none;
                border-radius: 8px;
            }}
            QPushButton:hover {{
                background-color: {Colors.BG_CARD};
            }}
        """)
        user.setCursor(Qt.PointingHandCursor)
        layout.addWidget(user)

    def _make_action_button(self, text: str, bg: str, hover_bg: str) -> QPushButton:
        btn = QPushButton(text)
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg};
                color: {Colors.TEXT_PRIMARY};
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-family: {Fonts.FAMILY};
                font-size: 12px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {hover_bg};
            }}
            QPushButton:pressed {{
                background-color: {bg}CC;
            }}
            QPushButton:checked {{
                background-color: {hover_bg};
            }}
        """)
        btn.setCursor(Qt.PointingHandCursor)
        btn.setIconSize(QSize(14, 14))
        return btn

    def set_scanning(self, scanning: bool) -> None:
        if scanning:
            self._scan_btn.setText("  Scanning...")
            self._scan_btn.setEnabled(False)
        else:
            self._scan_btn.setText("  Start Scan")
            self._scan_btn.setEnabled(True)

    def set_auto_refresh(self, enabled: bool) -> None:
        self._auto_btn.setChecked(enabled)

    def get_search_text(self) -> str:
        return self._search.text()
