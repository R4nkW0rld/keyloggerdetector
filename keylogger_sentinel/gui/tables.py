"""Custom table widget for displaying process findings."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import customtkinter as ctk
except ImportError:
    import tkinter as tk
    ctk = None

from core.models import Finding, Severity


class FindingTable:
    """Scrollable table widget displaying scan findings with color coding.

    Uses a treeview-style layout built from CTk widgets for a native
    look on all platforms.
    """

    COLUMNS = [
        ("PID", 70),
        ("Name", 180),
        ("Severity", 80),
        ("Score", 60),
        ("CPU%", 60),
        ("Mem MB", 70),
        ("SHA-256 (prefix)", 120),
    ]

    def __init__(self, parent: Any, on_select: Callable[[Optional[Finding]], None] | None = None) -> None:
        self._parent = parent
        self._on_select = on_select
        self._findings: List[Finding] = []
        self._selected_index: int | None = None
        self._row_widgets: List[Tuple[int, Any, Any]] = []  # (pid, frame, label_widgets)

        # Container with scrollbar
        if ctk:
            self.container = ctk.CTkFrame(parent)
        else:
            self.container = tk.Frame(parent)

        # Header row
        self._build_header()
        # Scrollable body
        self._build_body()

    def _build_header(self) -> None:
        if ctk:
            header = ctk.CTkFrame(self.container, fg_color="#34495e")
        else:
            header = tk.Frame(self.container, bg="#34495e")
        header.pack(fill="x")

        for col_name, width in self.COLUMNS:
            if ctk:
                lbl = ctk.CTkLabel(
                    header, text=col_name, width=width,
                    anchor="w", font=ctk.CTkFont(size=12, weight="bold"),
                    text_color="white",
                )
            else:
                lbl = tk.Label(
                    header, text=col_name, width=width // 8,
                    anchor="w", font=("Arial", 10, "bold"),
                    bg="#34495e", fg="white",
                )
            lbl.pack(side="left", padx=1, pady=4)

    def _build_body(self) -> None:
        if ctk:
            self._body_frame = ctk.CTkScrollableFrame(self.container, height=400)
        else:
            canvas = tk.Canvas(self.container, highlightthickness=0)
            scrollbar = tk.Scrollbar(self.container, orient="vertical", command=canvas.yview)
            self._body_frame = tk.Frame(canvas)
            canvas.create_window((0, 0), window=self._body_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            self._body_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
            )

        self._body_frame.pack(fill="both", expand=True)
        self.container.pack(fill="both", expand=True)

    def update_findings(self, findings: List[Finding]) -> None:
        """Replace all rows with new findings."""
        self._findings = findings
        self._selected_index = None
        self._rebuild_rows()

    def _rebuild_rows(self) -> None:
        """Rebuild all visible rows."""
        # Clear existing
        for widget in self._body_frame.winfo_children():
            widget.destroy()
        self._row_widgets.clear()

        for idx, f in enumerate(self._findings):
            self._add_row(idx, f)

    def _add_row(self, idx: int, finding: Finding) -> None:
        """Add a single row for a finding."""
        if ctk:
            row_frame = ctk.CTkFrame(self._body_frame, height=32)
        else:
            row_frame = tk.Frame(self._body_frame, height=32)

        bg = self._severity_bg(finding.severity)
        is_selected = (idx == self._selected_index)

        if ctk:
            row_frame.configure(fg_color=bg if is_selected else ("#f0f0f0", "#2b2b2b"))
        else:
            row_frame.configure(bg=bg if is_selected else "#f0f0f0")
        row_frame.pack(fill="x", padx=2, pady=1)
        row_frame.bind("<Button-1>", lambda e, i=idx: self._on_row_click(i))

        values = [
            str(finding.process.pid),
            finding.process.name[:25],
            finding.severity.label,
            str(finding.risk_score),
            f"{finding.process.cpu_percent:.1f}",
            f"{finding.process.memory_mb:.1f}",
            finding.sha256[:16] + "..." if finding.sha256 else "N/A",
        ]

        widgets = []
        for i, (col_name, width) in enumerate(self.COLUMNS):
            text = values[i] if i < len(values) else ""
            color = "white" if is_selected else "#2c3e50"
            if ctk:
                lbl = ctk.CTkLabel(
                    row_frame, text=text, width=width,
                    anchor="w", font=ctk.CTkFont(size=11),
                    text_color=color,
                )
            else:
                lbl = tk.Label(
                    row_frame, text=text, width=width // 8,
                    anchor="w", font=("Arial", 9),
                    bg=row_frame["bg"], fg=color,
                )
            lbl.pack(side="left", padx=1, pady=2)
            lbl.bind("<Button-1>", lambda e, i=idx: self._on_row_click(i))
            widgets.append(lbl)

        self._row_widgets.append((finding.process.pid, row_frame, widgets))

    def _on_row_click(self, idx: int) -> None:
        """Handle row click."""
        self._selected_index = idx
        self._rebuild_rows()
        if self._on_select and 0 <= idx < len(self._findings):
            self._on_select(self._findings[idx])

    def _severity_bg(self, severity: Severity) -> str:
        """Get background color for a severity level."""
        colors = {
            Severity.LOW: "#d5f5e3",
            Severity.MEDIUM: "#fdebd0",
            Severity.HIGH: "#fadbd8",
            Severity.CRITICAL: "#e8daef",
        }
        return colors.get(severity, "#f0f0f0")

    def clear(self) -> None:
        """Clear all rows."""
        self._findings.clear()
        self._selected_index = None
        self._rebuild_rows()

    @property
    def selected(self) -> Finding | None:
        if self._selected_index is not None and 0 <= self._selected_index < len(self._findings):
            return self._findings[self._selected_index]
        return None
