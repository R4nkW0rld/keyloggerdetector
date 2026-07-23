"""Pure QPainter icon rendering for Keylogger Detector UI.

No QtSvg dependency required - all icons are drawn programmatically
using QPainterPath for crisp vector rendering at any size.
"""

from __future__ import annotations

import math
from PySide6.QtGui import QIcon, QPixmap, QColor, QPainter, QPen, QBrush, QPainterPath
from PySide6.QtCore import Qt, QPointF, QRectF

from ui.theme import Colors


def _make_icon(paint_func, size: int = 20, color: str | None = None) -> QIcon:
    """Create a QIcon by calling paint_func(painter, rect, color)."""
    c = QColor(color or Colors.TEXT_PRIMARY)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
    rect = QRectF(0, 0, size, size)
    paint_func(painter, rect, c)
    painter.end()
    return QIcon(pixmap)


def _pen(color: QColor, width: float = 1.5) -> QPen:
    pen = QPen(color, width, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    return pen


def _scale(val: float, total: float, target: float) -> float:
    return val / total * target


# ---- Icon paint functions ----

def _paint_shield(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    path = QPainterPath()
    cx, cy = s / 2, s / 2
    path.moveTo(cx, s * 0.08)
    path.lineTo(s * 0.88, s * 0.22)
    path.lineTo(s * 0.82, s * 0.65)
    path.cubicTo(s * 0.7, s * 0.82, cx, s * 0.94, cx, s * 0.94)
    path.cubicTo(cx, s * 0.94, s * 0.3, s * 0.82, s * 0.18, s * 0.65)
    path.lineTo(s * 0.12, s * 0.22)
    path.closeSubpath()
    p.drawPath(path)


def _paint_shield_check(p: QPainter, r: QRectF, c: QColor):
    _paint_shield(p, r, c)
    s = r.width()
    p.setPen(_pen(c, s * 0.09))
    path = QPainterPath()
    path.moveTo(s * 0.35, s * 0.52)
    path.lineTo(s * 0.47, s * 0.64)
    path.lineTo(s * 0.67, s * 0.38)
    p.drawPath(path)


def _paint_search(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawEllipse(QPointF(s * 0.42, s * 0.42), s * 0.28, s * 0.28)
    p.drawLine(QPointF(s * 0.63, s * 0.63), QPointF(s * 0.88, s * 0.88))


def _paint_bell(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    path = QPainterPath()
    path.moveTo(s * 0.22, s * 0.55)
    path.cubicTo(s * 0.22, s * 0.28, s * 0.78, s * 0.28, s * 0.78, s * 0.55)
    path.lineTo(s * 0.82, s * 0.65)
    path.lineTo(s * 0.18, s * 0.65)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(QPointF(s * 0.42, s * 0.78), QPointF(s * 0.58, s * 0.78))
    p.drawEllipse(QPointF(s * 0.5, s * 0.18), s * 0.04, s * 0.04)


def _paint_settings(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.12, s * 0.12)
    for i in range(8):
        angle = math.radians(i * 45)
        x1 = s * 0.5 + math.cos(angle) * s * 0.20
        y1 = s * 0.5 + math.sin(angle) * s * 0.20
        x2 = s * 0.5 + math.cos(angle) * s * 0.30
        y2 = s * 0.5 + math.sin(angle) * s * 0.30
        p.drawLine(QPointF(x1, y1), QPointF(x2, y2))


def _paint_user(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawEllipse(QPointF(s * 0.5, s * 0.34), s * 0.14, s * 0.14)
    path = QPainterPath()
    path.moveTo(s * 0.18, s * 0.92)
    path.cubicTo(s * 0.18, s * 0.66, s * 0.82, s * 0.66, s * 0.82, s * 0.92)
    p.drawPath(path)


def _paint_play(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(c))
    path = QPainterPath()
    path.moveTo(s * 0.28, s * 0.16)
    path.lineTo(s * 0.82, s * 0.50)
    path.lineTo(s * 0.28, s * 0.84)
    path.closeSubpath()
    p.drawPath(path)


def _paint_refresh(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawArc(QRectF(s * 0.16, s * 0.16, s * 0.68, s * 0.68), 30 * 16, 280 * 16)
    p.drawLine(QPointF(s * 0.5, s * 0.16), QPointF(s * 0.7, s * 0.16))
    p.drawLine(QPointF(s * 0.5, s * 0.16), QPointF(s * 0.5, s * 0.04))
    p.drawLine(QPointF(s * 0.5, s * 0.04), QPointF(s * 0.68, s * 0.16))


def _paint_download(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawLine(QPointF(s * 0.5, s * 0.14), QPointF(s * 0.5, s * 0.68))
    p.drawLine(QPointF(s * 0.34, s * 0.54), QPointF(s * 0.5, s * 0.68))
    p.drawLine(QPointF(s * 0.66, s * 0.54), QPointF(s * 0.5, s * 0.68))
    p.drawLine(QPointF(s * 0.18, s * 0.82), QPointF(s * 0.82, s * 0.82))


def _paint_check(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.10))
    p.setBrush(Qt.NoBrush)
    path = QPainterPath()
    path.moveTo(s * 0.20, s * 0.52)
    path.lineTo(s * 0.42, s * 0.74)
    path.lineTo(s * 0.80, s * 0.28)
    p.drawPath(path)


def _paint_folder(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    path = QPainterPath()
    path.moveTo(s * 0.10, s * 0.30)
    path.lineTo(s * 0.40, s * 0.30)
    path.lineTo(s * 0.46, s * 0.22)
    path.lineTo(s * 0.82, s * 0.22)
    path.cubicTo(s * 0.86, s * 0.22, s * 0.88, s * 0.26, s * 0.88, s * 0.30)
    path.lineTo(s * 0.88, s * 0.76)
    path.cubicTo(s * 0.88, s * 0.80, s * 0.86, s * 0.82, s * 0.82, s * 0.82)
    path.lineTo(s * 0.18, s * 0.82)
    path.cubicTo(s * 0.14, s * 0.82, s * 0.12, s * 0.80, s * 0.12, s * 0.76)
    path.lineTo(s * 0.10, s * 0.34)
    path.cubicTo(s * 0.10, s * 0.32, s * 0.10, s * 0.30, s * 0.10, s * 0.30)
    p.drawPath(path)


def _paint_copy(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawRoundedRect(QRectF(s * 0.14, s * 0.30, s * 0.52, s * 0.58), s * 0.04, s * 0.04)
    p.drawRoundedRect(QRectF(s * 0.34, s * 0.12, s * 0.52, s * 0.58), s * 0.04, s * 0.04)


def _paint_stop(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawEllipse(QPointF(s * 0.5, s * 0.5), s * 0.38, s * 0.38)
    p.drawLine(QPointF(s * 0.32, s * 0.32), QPointF(s * 0.68, s * 0.68))


def _paint_alert_triangle(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    path = QPainterPath()
    path.moveTo(s * 0.50, s * 0.12)
    path.lineTo(s * 0.90, s * 0.84)
    path.lineTo(s * 0.10, s * 0.84)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(QPointF(s * 0.50, s * 0.40), QPointF(s * 0.50, s * 0.62))
    p.drawEllipse(QPointF(s * 0.50, s * 0.72), s * 0.025, s * 0.025)


def _paint_cpu(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawRoundedRect(QRectF(s * 0.22, s * 0.22, s * 0.56, s * 0.56), s * 0.04, s * 0.04)
    p.drawRoundedRect(QRectF(s * 0.38, s * 0.38, s * 0.24, s * 0.24), s * 0.02, s * 0.02)
    pins = [(0.38, 0.00, 0.38, 0.18), (0.50, 0.00, 0.50, 0.18), (0.62, 0.00, 0.62, 0.18),
            (0.38, 0.82, 0.38, 1.0), (0.50, 0.82, 0.50, 1.0), (0.62, 0.82, 0.62, 1.0),
            (0.00, 0.38, 0.18, 0.38), (0.00, 0.50, 0.18, 0.50), (0.00, 0.62, 0.18, 0.62),
            (0.82, 0.38, 1.0, 0.38), (0.82, 0.50, 1.0, 0.50), (0.82, 0.62, 1.0, 0.62)]
    for x1, y1, x2, y2 in pins:
        p.drawLine(QPointF(s * x1, s * y1), QPointF(s * x2, s * y2))


def _paint_memory(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawRoundedRect(QRectF(s * 0.08, s * 0.28, s * 0.84, s * 0.44), s * 0.04, s * 0.04)
    for x in [0.28, 0.42, 0.56, 0.70]:
        p.drawLine(QPointF(s * x, s * 0.42), QPointF(s * x, s * 0.58))


def _paint_key(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawEllipse(QPointF(s * 0.34, s * 0.40), s * 0.18, s * 0.18)
    p.drawLine(QPointF(s * 0.48, s * 0.40), QPointF(s * 0.88, s * 0.40))
    p.drawLine(QPointF(s * 0.76, s * 0.40), QPointF(s * 0.76, s * 0.52))
    p.drawLine(QPointF(s * 0.86, s * 0.40), QPointF(s * 0.86, s * 0.48))


def _paint_eye(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    path = QPainterPath()
    path.moveTo(s * 0.06, s * 0.50)
    path.cubicTo(s * 0.06, s * 0.18, s * 0.94, s * 0.18, s * 0.94, s * 0.50)
    path.cubicTo(s * 0.94, s * 0.82, s * 0.06, s * 0.82, s * 0.06, s * 0.50)
    p.drawPath(path)
    p.drawEllipse(QPointF(s * 0.50, s * 0.50), s * 0.14, s * 0.14)
    p.setBrush(QBrush(c))
    p.drawEllipse(QPointF(s * 0.50, s * 0.50), s * 0.06, s * 0.06)
    p.setBrush(Qt.NoBrush)


def _paint_database(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawEllipse(QPointF(s * 0.50, s * 0.26), s * 0.36, s * 0.12)
    path = QPainterPath()
    path.moveTo(s * 0.14, s * 0.26)
    path.lineTo(s * 0.14, s * 0.74)
    path.cubicTo(s * 0.14, s * 0.86, s * 0.86, s * 0.86, s * 0.86, s * 0.74)
    path.lineTo(s * 0.86, s * 0.26)
    p.drawPath(path)
    p.drawEllipse(QPointF(s * 0.50, s * 0.50), s * 0.36, s * 0.12)
    p.drawEllipse(QPointF(s * 0.50, s * 0.74), s * 0.36, s * 0.12)


def _paint_clock(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawEllipse(QPointF(s * 0.50, s * 0.50), s * 0.38, s * 0.38)
    p.drawLine(QPointF(s * 0.50, s * 0.50), QPointF(s * 0.50, s * 0.26))
    p.drawLine(QPointF(s * 0.50, s * 0.50), QPointF(s * 0.66, s * 0.62))


def _paint_hash(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.10))
    p.drawLine(QPointF(s * 0.22, s * 0.34), QPointF(s * 0.14, s * 0.76))
    p.drawLine(QPointF(s * 0.78, s * 0.24), QPointF(s * 0.70, s * 0.86))
    p.drawLine(QPointF(s * 0.08, s * 0.50), QPointF(s * 0.92, s * 0.50))
    p.drawLine(QPointF(s * 0.30, s * 0.14), QPointF(s * 0.22, s * 0.96))


def _paint_file_text(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    path = QPainterPath()
    path.moveTo(s * 0.22, s * 0.08)
    path.lineTo(s * 0.64, s * 0.08)
    path.lineTo(s * 0.78, s * 0.22)
    path.lineTo(s * 0.78, s * 0.92)
    path.lineTo(s * 0.22, s * 0.92)
    path.closeSubpath()
    p.drawPath(path)
    for y in [0.38, 0.54, 0.70]:
        p.drawLine(QPointF(s * 0.34, s * y), QPointF(s * 0.66, s * y))


def _paint_close(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.10))
    p.drawLine(QPointF(s * 0.24, s * 0.24), QPointF(s * 0.76, s * 0.76))
    p.drawLine(QPointF(s * 0.76, s * 0.24), QPointF(s * 0.24, s * 0.76))


def _paint_activity(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.08))
    p.setBrush(Qt.NoBrush)
    path = QPainterPath()
    path.moveTo(s * 0.06, s * 0.56)
    path.lineTo(s * 0.26, s * 0.56)
    path.lineTo(s * 0.36, s * 0.20)
    path.lineTo(s * 0.50, s * 0.82)
    path.lineTo(s * 0.64, s * 0.38)
    path.lineTo(s * 0.74, s * 0.56)
    path.lineTo(s * 0.94, s * 0.56)
    p.drawPath(path)


def _paint_filter(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    path = QPainterPath()
    path.moveTo(s * 0.10, s * 0.18)
    path.lineTo(s * 0.90, s * 0.18)
    path.lineTo(s * 0.56, s * 0.52)
    path.lineTo(s * 0.56, s * 0.78)
    path.lineTo(s * 0.44, s * 0.88)
    path.lineTo(s * 0.44, s * 0.52)
    path.closeSubpath()
    p.drawPath(path)


def _paint_lock(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    path = QPainterPath()
    path.moveTo(s * 0.32, s * 0.44)
    path.lineTo(s * 0.32, s * 0.30)
    path.cubicTo(s * 0.32, s * 0.12, s * 0.68, s * 0.12, s * 0.68, s * 0.30)
    path.lineTo(s * 0.68, s * 0.44)
    p.drawPath(path)
    p.drawRoundedRect(QRectF(s * 0.22, s * 0.44, s * 0.56, s * 0.44), s * 0.04, s * 0.04)
    p.drawEllipse(QPointF(s * 0.50, s * 0.58), s * 0.04, s * 0.04)


def _paint_external_link(p: QPainter, r: QRectF, c: QColor):
    s = r.width()
    p.setPen(_pen(c, s * 0.07))
    p.setBrush(Qt.NoBrush)
    p.drawLine(QPointF(s * 0.42, s * 0.82), QPointF(s * 0.82, s * 0.82))
    p.drawLine(QPointF(s * 0.82, s * 0.42), QPointF(s * 0.82, s * 0.82))
    p.drawLine(QPointF(s * 0.82, s * 0.42), QPointF(s * 0.52, s * 0.18))


# ---- Public API ----

def shield_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_shield, size, color)

def search_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_search, size, color)

def bell_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_bell, size, color)

def settings_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_settings, size, color)

def user_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_user, size, color)

def play_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_play, size, color)

def refresh_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_refresh, size, color)

def download_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_download, size, color)

def check_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_check, size, color)

def folder_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_folder, size, color)

def copy_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_copy, size, color)

def stop_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_stop, size, color)

def shield_check_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_shield_check, size, color)

def alert_triangle_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_alert_triangle, size, color)

def cpu_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_cpu, size, color)

def memory_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_memory, size, color)

def key_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_key, size, color)

def eye_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_eye, size, color)

def database_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_database, size, color)

def clock_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_clock, size, color)

def hash_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_hash, size, color)

def file_text_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_file_text, size, color)

def close_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_close, size, color)

def activity_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_activity, size, color)

def filter_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_filter, size, color)

def lock_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_lock, size, color)

def external_link_icon(size: int = 20, color: str | None = None) -> QIcon:
    return _make_icon(_paint_external_link, size, color)
