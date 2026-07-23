"""Modern process table widget for displaying scan findings."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QLabel, QStyledItemDelegate,
    QStyleOptionViewItem,
)
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QColor, QFont, QBrush, QPainter, QPen

from ui.theme import Colors, Fonts, severity_color, severity_bg


class SeverityBadgeDelegate(QStyledItemDelegate):
    """Custom delegate that renders severity as a colored badge."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index):
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)

        severity = index.data(Qt.UserRole + 1) or index.data(Qt.DisplayRole)
        color = severity_color(str(severity))
        bg = severity_bg(str(severity))

        rect = option.rect
        badge_rect = rect.adjusted(8, 6, -8, -6)

        painter.setBrush(QColor(bg))
        painter.setPen(QPen(QColor(color + "40"), 1))
        painter.drawRoundedRect(badge_rect, 6, 6)

        painter.setPen(QColor(color))
        font = QFont(Fonts.FAMILY.split(",")[0].strip(), 10)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(badge_rect, Qt.AlignCenter, str(severity))

        painter.restore()

    def sizeHint(self, option, index):
        return QSize(0, 36)


class ProcessTable(QFrame):
    """Modern styled table for displaying process findings."""

    finding_selected = Signal(object)
    finding_double_clicked = Signal(object)

    COLUMNS = [
        ("PID", 70),
        ("Process Name", 200),
        ("Severity", 100),
        ("Risk Score", 90),
        ("CPU %", 80),
        ("Memory MB", 90),
        ("SHA-256", 280),
        ("Status", 90),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._findings: list = []
        self.setObjectName("ProcessTableContainer")
        self.setStyleSheet(f"""
            QFrame#ProcessTableContainer {{
                background-color: {Colors.BG_PANEL};
                border: 1px solid {Colors.BORDER};
                border-radius: 12px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header_bar = QFrame()
        header_bar.setFixedHeight(44)
        header_bar.setStyleSheet(f"""
            background-color: {Colors.BG_CARD};
            border-top-left-radius: 12px;
            border-top-right-radius: 12px;
            border-bottom: 1px solid {Colors.BORDER};
        """)
        header_layout = QHBoxLayout(header_bar)
        header_layout.setContentsMargins(16, 0, 16, 0)

        title = QLabel("Process Monitor")
        title.setStyleSheet(f"""
            font-family: {Fonts.FAMILY};
            font-size: 14px;
            font-weight: 600;
            color: {Colors.TEXT_PRIMARY};
            background: transparent;
        """)
        header_layout.addWidget(title)
        header_layout.addStretch()

        self._count_label = QLabel("0 findings")
        self._count_label.setStyleSheet(f"""
            font-family: {Fonts.FAMILY};
            font-size: 12px;
            color: {Colors.TEXT_MUTED};
            background: transparent;
        """)
        header_layout.addWidget(self._count_label)

        layout.addWidget(header_bar)

        self._table = QTableWidget()
        self._setup_table()
        layout.addWidget(self._table)

    def _setup_table(self):
        table = self._table
        table.setColumnCount(len(self.COLUMNS))
        table.setHorizontalHeaderLabels([c[0] for c in self.COLUMNS])

        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.setSortingEnabled(True)

        table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {Colors.BG_PANEL};
                border: none;
                border-radius: 0 0 12px 12px;
                gridline-color: transparent;
                outline: none;
                font-family: {Fonts.FAMILY};
                font-size: 12px;
                color: {Colors.TEXT_PRIMARY};
            }}
            QTableWidget::item {{
                padding: 4px 12px;
                border: none;
                background-color: {Colors.ROW_EVEN};
            }}
            QTableWidget::item:alternate {{
                background-color: {Colors.ROW_ODD};
            }}
            QTableWidget::item:selected {{
                background-color: {Colors.ROW_SELECTED};
                color: {Colors.TEXT_PRIMARY};
            }}
            QTableWidget::item:hover {{
                background-color: {Colors.ROW_HOVER};
            }}
            QHeaderView::section {{
                background-color: {Colors.BG_CARD};
                color: {Colors.TEXT_SECONDARY};
                border: none;
                border-bottom: 1px solid {Colors.BORDER};
                border-right: 1px solid {Colors.BORDER};
                padding: 8px 12px;
                font-family: {Fonts.FAMILY};
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            QHeaderView::section:last {{
                border-right: none;
            }}
            QHeaderView::section:hover {{
                background-color: {Colors.BG_CARD_HOVER};
            }}
        """)

        header = table.horizontalHeader()
        header.setStretchLastSection(True)
        for i, (_, width) in enumerate(self.COLUMNS):
            header.resizeSection(i, width)
            header.setSectionResizeMode(i, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Stretch)

        table.verticalHeader().setDefaultSectionSize(38)

        badge_delegate = SeverityBadgeDelegate(table)
        table.setItemDelegateForColumn(2, badge_delegate)

        table.itemSelectionChanged.connect(self._on_selection_changed)
        table.doubleClicked.connect(self._on_double_click)

    def set_findings(self, findings: list) -> None:
        self._findings = findings
        self._count_label.setText(f"{len(findings)} finding{'s' if len(findings) != 1 else ''}")
        self._table.clearSelection()
        self._populate_table()

    def filter_findings(self, text: str) -> None:
        text_lower = text.lower().strip()
        for row in range(self._table.rowCount()):
            show = True
            if text_lower:
                row_text = ""
                for col in range(self._table.columnCount()):
                    item = self._table.item(row, col)
                    if item:
                        row_text += item.text().lower() + " "
                show = text_lower in row_text
            self._table.setRowHidden(row, not show)

    def _populate_table(self):
        table = self._table
        table.setSortingEnabled(False)
        table.setRowCount(len(self._findings))

        for row, finding in enumerate(self._findings):
            proc = finding.process
            severity = finding.severity.label

            items_data = [
                str(proc.pid),
                proc.name,
                severity,
                str(finding.risk_score),
                f"{proc.cpu_percent:.1f}",
                f"{proc.memory_mb:.1f}",
                finding.sha256 if finding.sha256 else "N/A",
                "Active" if proc.status == "running" else proc.status,
            ]

            for col, text in enumerate(items_data):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                item.setData(Qt.UserRole, finding)
                if col == 2:
                    item.setData(Qt.UserRole + 1, severity)
                item.setForeground(QBrush(QColor(Colors.TEXT_PRIMARY)))

                font = QFont(Fonts.FAMILY.split(",")[0].strip(), 11)
                if col == 0:
                    font.setFamily(Fonts.MONO.split(",")[0].strip())
                    font.setBold(True)
                elif col == 3:
                    score = finding.risk_score
                    if score >= 76:
                        item.setForeground(QBrush(QColor(Colors.SEVERITY_CRITICAL)))
                    elif score >= 51:
                        item.setForeground(QBrush(QColor(Colors.SEVERITY_HIGH)))
                    elif score >= 26:
                        item.setForeground(QBrush(QColor(Colors.SEVERITY_MEDIUM)))
                    else:
                        item.setForeground(QBrush(QColor(Colors.SEVERITY_LOW)))
                    font.setBold(True)
                elif col == 6:
                    font.setFamily(Fonts.MONO.split(",")[0].strip())
                    font.setPointSize(9)
                    item.setForeground(QBrush(QColor(Colors.TEXT_MUTED)))
                elif col == 7:
                    color = Colors.SUCCESS if text == "Active" else Colors.TEXT_MUTED
                    item.setForeground(QBrush(QColor(color)))

                item.setFont(font)
                table.setItem(row, col, item)

        table.setSortingEnabled(True)

    def _on_selection_changed(self):
        sel_model = self._table.selectionModel()
        if sel_model is None:
            return
        rows = sel_model.selectedRows()
        if rows:
            row = rows[0].row()
            item = self._table.item(row, 0)
            if item:
                finding = item.data(Qt.UserRole)
                self.finding_selected.emit(finding)
        else:
            self.finding_selected.emit(None)

    def _on_double_click(self, index):
        item = self._table.item(index.row(), 0)
        if item:
            finding = item.data(Qt.UserRole)
            self.finding_double_clicked.emit(finding)

    def get_selected_finding(self):
        sel_model = self._table.selectionModel()
        if sel_model is None:
            return None
        rows = sel_model.selectedRows()
        if rows:
            item = self._table.item(rows[0].row(), 0)
            if item:
                return item.data(Qt.UserRole)
        return None

    def clear(self):
        self._findings.clear()
        self._table.clearSelection()
        self._table.setRowCount(0)
        self._count_label.setText("0 findings")
