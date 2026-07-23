"""Statistics cards widget for the dashboard."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QVBoxLayout, QLabel, QGraphicsDropShadowEffect,
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QColor, QFont, QIcon

from ui.theme import Colors, Fonts


class StatCard(QFrame):
    """A single statistics card with animated number display."""

    def __init__(
        self,
        title: str,
        value: int = 0,
        color: str = Colors.ACCENT,
        icon: QIcon | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self._color = color
        self._display_value = 0
        self._target_value = value

        self.setObjectName("StatCard")
        self.setFixedSize(160, 100)
        self.setCursor(Qt.PointingHandCursor)

        self.setStyleSheet(f"""
            QFrame#StatCard {{
                background-color: {Colors.BG_CARD};
                border: 1px solid {Colors.BORDER};
                border-radius: 12px;
            }}
            QFrame#StatCard:hover {{
                border: 1px solid {color}40;
                background-color: {Colors.BG_CARD_HOVER};
            }}
        """)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 40))
        shadow.setOffset(0, 4)
        self.setGraphicsEffect(shadow)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        if icon:
            icon_label = QLabel()
            icon_label.setPixmap(icon.pixmap(QSize(18, 18)))
            icon_label.setFixedSize(18, 18)
            top_row.addWidget(icon_label)

        self._value_label = QLabel("0")
        self._value_label.setStyleSheet(f"""
            font-family: {Fonts.FAMILY};
            font-size: 28px;
            font-weight: bold;
            color: {color};
            background: transparent;
        """)
        top_row.addWidget(self._value_label)
        top_row.addStretch()

        layout.addLayout(top_row)

        self._title_label = QLabel(title)
        self._title_label.setStyleSheet(f"""
            font-family: {Fonts.FAMILY};
            font-size: 11px;
            font-weight: 500;
            color: {Colors.TEXT_SECONDARY};
            background: transparent;
            letter-spacing: 0.5px;
        """)
        layout.addWidget(self._title_label)

        layout.addStretch()

        self._bar = QFrame()
        self._bar.setFixedHeight(3)
        self._bar.setStyleSheet(f"""
            background-color: {color}30;
            border-radius: 1px;
        """)
        layout.addWidget(self._bar)

        self._indicator = QFrame(self._bar)
        self._indicator.setStyleSheet(f"""
            background-color: {color};
            border-radius: 1px;
        """)
        self._indicator.setGeometry(0, 0, 0, 3)

    def update_value(self, value: int) -> None:
        self._target_value = value
        self._display_value = value
        self._value_label.setText(str(value))
        bar_width = self._bar.width()
        if bar_width > 0:
            indicator_w = min(value, bar_width)
            self._indicator.setGeometry(0, 0, indicator_w, 3)

    @property
    def display_value(self):
        return self._display_value


class StatsRow(QFrame):
    """Row of all statistics cards."""

    CARD_DEFS = [
        ("Processes", Colors.ACCENT, "processes"),
        ("Scanned", Colors.SUCCESS, "scanned"),
        ("Critical", Colors.SEVERITY_CRITICAL, "critical"),
        ("High", Colors.SEVERITY_HIGH, "high"),
        ("Medium", Colors.SEVERITY_MEDIUM, "medium"),
        ("Low", Colors.SEVERITY_LOW, "low"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background: transparent; border: none;")
        self.setFixedHeight(110)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 0, 4, 0)
        layout.setSpacing(12)

        self._cards: dict[str, StatCard] = {}

        from ui.icons import (
            cpu_icon, shield_check_icon, alert_triangle_icon,
            alert_triangle_icon as warn_icon, key_icon, shield_icon,
        )

        icon_map = {
            "processes": cpu_icon(18, Colors.ACCENT),
            "scanned": shield_check_icon(18, Colors.SUCCESS),
            "critical": alert_triangle_icon(18, Colors.SEVERITY_CRITICAL),
            "high": warn_icon(18, Colors.SEVERITY_HIGH),
            "medium": key_icon(18, Colors.SEVERITY_MEDIUM),
            "low": shield_icon(18, Colors.SEVERITY_LOW),
        }

        for title, color, key in self.CARD_DEFS:
            card = StatCard(title, 0, color, icon_map.get(key))
            self._cards[key] = card
            layout.addWidget(card)

        layout.addStretch()

    def update_from_result(self, result) -> None:
        self._cards["processes"].update_value(result.total_processes)
        self._cards["scanned"].update_value(result.scanned_processes)
        self._cards["critical"].update_value(result.critical_count)
        self._cards["high"].update_value(result.high_count)
        self._cards["medium"].update_value(result.medium_count)
        self._cards["low"].update_value(result.low_count)
