"""Theme constants and stylesheet for Keylogger Detector."""

from __future__ import annotations


class Colors:
    BG_PRIMARY = "#0D1117"
    BG_PANEL = "#161B22"
    BG_CARD = "#1E293B"
    BG_CARD_HOVER = "#253349"
    BG_INPUT = "#0D1117"
    BORDER = "#30363D"
    BORDER_LIGHT = "#3D444D"
    ACCENT = "#3B82F6"
    ACCENT_HOVER = "#2563EB"
    ACCENT_LIGHT = "#1D4ED8"
    SUCCESS = "#22C55E"
    SUCCESS_BG = "#052E16"
    WARNING = "#F59E0B"
    WARNING_BG = "#451A03"
    DANGER = "#EF4444"
    DANGER_BG = "#450A0A"
    PURPLE = "#8B5CF6"
    PURPLE_BG = "#2E1065"
    TEXT_PRIMARY = "#F8FAFC"
    TEXT_SECONDARY = "#94A3B8"
    TEXT_MUTED = "#64748B"
    SEVERITY_CRITICAL = "#EF4444"
    SEVERITY_HIGH = "#F97316"
    SEVERITY_MEDIUM = "#F59E0B"
    SEVERITY_LOW = "#22C55E"
    SEVERITY_CLEAN = "#3B82F6"
    ROW_EVEN = "#161B22"
    ROW_ODD = "#1C2333"
    ROW_HOVER = "#1F2D44"
    ROW_SELECTED = "#172554"
    SCROLLBAR_BG = "#1E293B"
    SCROLLBAR_HANDLE = "#30363D"


class Fonts:
    FAMILY = "Inter, Segoe UI, SF Pro Display, Roboto, Helvetica Neue, Arial, sans-serif"
    MONO = "JetBrains Mono, Fira Code, SF Mono, Consolas, monospace"

    @staticmethod
    def heading(size: int = 16, weight: str = "bold") -> str:
        return f"font-family: {Fonts.FAMILY}; font-size: {size}px; font-weight: {weight};"

    @staticmethod
    def body(size: int = 13, weight: str = "normal") -> str:
        return f"font-family: {Fonts.FAMILY}; font-size: {size}px; font-weight: {weight};"

    @staticmethod
    def mono(size: int = 11, weight: str = "normal") -> str:
        return f"font-family: {Fonts.MONO}; font-size: {size}px; font-weight: {weight};"


def severity_color(severity: str) -> str:
    mapping = {
        "Critical": Colors.SEVERITY_CRITICAL,
        "High": Colors.SEVERITY_HIGH,
        "Medium": Colors.SEVERITY_MEDIUM,
        "Low": Colors.SEVERITY_LOW,
        "Clean": Colors.SEVERITY_CLEAN,
    }
    return mapping.get(severity, Colors.TEXT_SECONDARY)


def severity_bg(severity: str) -> str:
    mapping = {
        "Critical": Colors.DANGER_BG,
        "High": "#431407",
        "Medium": Colors.WARNING_BG,
        "Low": Colors.SUCCESS_BG,
        "Clean": "#172554",
    }
    return mapping.get(severity, Colors.BG_CARD)


APP_STYLESHEET = f"""
* {{
    margin: 0;
    padding: 0;
}}

QMainWindow {{
    background-color: {Colors.BG_PRIMARY};
}}

QWidget {{
    background-color: transparent;
    color: {Colors.TEXT_PRIMARY};
    font-family: {Fonts.FAMILY};
    font-size: 13px;
}}

QScrollBar:vertical {{
    background: {Colors.SCROLLBAR_BG};
    width: 8px;
    border-radius: 4px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {Colors.SCROLLBAR_HANDLE};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {Colors.TEXT_MUTED};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: none;
}}

QScrollBar:horizontal {{
    background: {Colors.SCROLLBAR_BG};
    height: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal {{
    background: {Colors.SCROLLBAR_HANDLE};
    border-radius: 4px;
    min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {Colors.TEXT_MUTED};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    background: none;
}}

QToolTip {{
    background-color: {Colors.BG_CARD};
    color: {Colors.TEXT_PRIMARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}}

QMenu {{
    background-color: {Colors.BG_PANEL};
    border: 1px solid {Colors.BORDER};
    border-radius: 8px;
    padding: 4px;
}}
QMenu::item {{
    padding: 8px 24px;
    border-radius: 4px;
    color: {Colors.TEXT_PRIMARY};
}}
QMenu::item:selected {{
    background-color: {Colors.ACCENT};
}}
QMenu::separator {{
    height: 1px;
    background: {Colors.BORDER};
    margin: 4px 8px;
}}

QDialog {{
    background-color: {Colors.BG_PANEL};
    border: 1px solid {Colors.BORDER};
    border-radius: 12px;
}}

QLineEdit {{
    background-color: {Colors.BG_INPUT};
    color: {Colors.TEXT_PRIMARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 13px;
    selection-background-color: {Colors.ACCENT};
}}
QLineEdit:focus {{
    border: 1px solid {Colors.ACCENT};
}}

QComboBox {{
    background-color: {Colors.BG_CARD};
    color: {Colors.TEXT_PRIMARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 13px;
}}
QComboBox:hover {{
    border: 1px solid {Colors.BORDER_LIGHT};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox::down-arrow {{
    image: none;
    border: none;
}}
QComboBox QAbstractItemView {{
    background-color: {Colors.BG_PANEL};
    color: {Colors.TEXT_PRIMARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 8px;
    selection-background-color: {Colors.ACCENT};
    outline: none;
    padding: 4px;
}}

QProgressBar {{
    background-color: {Colors.BG_INPUT};
    border: none;
    border-radius: 4px;
    height: 6px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    border-radius: 4px;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {Colors.ACCENT}, stop:1 {Colors.PURPLE});
}}
"""
