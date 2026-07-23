"""Reusable GUI widgets for Keylogger Detector."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

try:
    import customtkinter as ctk
except ImportError:
    import tkinter as tk
    ctk = None

from core.models import ScanResult, Severity


class StatusBar:
    """Status bar at the bottom of the main window."""

    def __init__(self, parent: Any) -> None:
        if ctk:
            self.frame = ctk.CTkFrame(parent, height=30)
            self.label = ctk.CTkLabel(
                self.frame, text="Ready", anchor="w",
                font=ctk.CTkFont(size=11),
            )
        else:
            self.frame = tk.Frame(parent, height=30, relief="sunken")
            self.label = tk.Label(
                self.frame, text="Ready", anchor="w",
                font=("Arial", 9),
            )
        self.label.pack(side="left", padx=10, fill="x", expand=True)
        self.frame.pack(fill="x", side="bottom")

    def set(self, text: str) -> None:
        self.label.configure(text=text)


class SummaryCards:
    """Summary statistics cards shown at the top of the dashboard."""

    def __init__(self, parent: Any) -> None:
        if ctk:
            self.frame = ctk.CTkFrame(parent, fg_color="transparent")
        else:
            self.frame = tk.Frame(parent)

        self._cards: Dict[str, Any] = {}
        card_defs = [
            ("total", "Processes", "#3495f5"),
            ("scanned", "Scanned", "#2ecc71"),
            ("critical", "Critical", "#8e44ad"),
            ("high", "High", "#e74c3c"),
            ("medium", "Medium", "#f39c12"),
            ("low", "Low", "#2ecc71"),
        ]

        for key, label, color in card_defs:
            if ctk:
                card = ctk.CTkFrame(self.frame, width=130, height=70)
                num_label = ctk.CTkLabel(
                    card, text="0", font=ctk.CTkFont(size=24, weight="bold"),
                    text_color=color,
                )
                text_label = ctk.CTkLabel(
                    card, text=label, font=ctk.CTkFont(size=10),
                    text_color="#7f8c8d",
                )
            else:
                card = tk.Frame(self.frame, width=130, height=70, relief="ridge", bd=1)
                num_label = tk.Label(
                    card, text="0", font=("Arial", 18, "bold"),
                    fg=color, bg=card["bg"],
                )
                text_label = tk.Label(
                    card, text=label, font=("Arial", 8),
                    fg="#7f8c8d", bg=card["bg"],
                )

            num_label.place(relx=0.5, rely=0.35, anchor="center")
            text_label.place(relx=0.5, rely=0.75, anchor="center")
            card.pack(side="left", padx=6, pady=5)
            self._cards[key] = num_label

        self.frame.pack(fill="x", pady=5)

    def update(self, result: ScanResult) -> None:
        """Update cards with scan results."""
        self._cards["total"].configure(text=str(result.total_processes))
        self._cards["scanned"].configure(text=str(result.scanned_processes))
        self._cards["critical"].configure(text=str(result.critical_count))
        self._cards["high"].configure(text=str(result.high_count))
        self._cards["medium"].configure(text=str(result.medium_count))
        self._cards["low"].configure(text=str(result.low_count))


class DetailSidebar:
    """Right-side panel showing detailed info about a selected finding."""

    def __init__(self, parent: Any, width: int = 380) -> None:
        if ctk:
            self.frame = ctk.CTkFrame(parent, width=width)
        else:
            self.frame = tk.Frame(parent, width=width)

        self.frame.pack_propagate(False)

        if ctk:
            self.title_label = ctk.CTkLabel(
                self.frame, text="Select a finding",
                font=ctk.CTkFont(size=14, weight="bold"),
                anchor="w",
            )
            self.title_label.pack(fill="x", padx=10, pady=(10, 5))

            self.scroll = ctk.CTkScrollableFrame(self.frame)
            self.scroll.pack(fill="both", expand=True, padx=5, pady=5)

            self.content_label = ctk.CTkLabel(
                self.scroll, text="", anchor="nw", justify="left",
                font=ctk.CTkFont(size=11, family="monospace"),
                wraplength=340,
            )
            self.content_label.pack(fill="x", padx=5, pady=5)
        else:
            self.title_label = tk.Label(
                self.frame, text="Select a finding",
                font=("Arial", 12, "bold"), anchor="w",
            )
            self.title_label.pack(fill="x", padx=10, pady=(10, 5))

            self.scroll = tk.Frame(self.frame)
            self.scroll.pack(fill="both", expand=True, padx=5, pady=5)

            self.content_label = tk.Label(
                self.scroll, text="", anchor="nw", justify="left",
                font=("Courier", 9), wraplength=340,
                bg=self.scroll["bg"],
            )
            self.content_label.pack(fill="x", padx=5, pady=5)

    def show_finding(self, finding) -> None:
        """Display details for a Finding."""
        if finding is None:
            self.clear()
            return

        self.title_label.configure(
            text=f"{finding.process.name} (PID {finding.process.pid})"
        )

        lines = [
            f"Severity:  {finding.severity.label}",
            f"Score:     {finding.risk_score}",
            f"Executable: {finding.process.exe}",
            f"Username:  {finding.process.username}",
            f"Parent:    {finding.process.parent_name}",
            f"CPU:       {finding.process.cpu_percent}%",
            f"Memory:    {finding.process.memory_mb} MB",
            f"Threads:   {finding.process.num_threads}",
            f"Status:    {finding.process.status}",
            f"SHA-256:   {finding.sha256[:32] if finding.sha256 else 'N/A'}",
            f"Known Bad: {'YES' if finding.known_bad_hash else 'No'}",
            "",
            "--- Risk Breakdown ---",
        ]

        for b in finding.breakdown:
            lines.append(f"  [{b.points:+d}] {b.reason}")

        if finding.network_indicators:
            lines.append("")
            lines.append("--- Network ---")
            for n in finding.network_indicators:
                if n.flagged:
                    lines.append(f"  {n.remote_addr}:{n.remote_port} ({n.status})")
                    for r in n.flag_reasons:
                        lines.append(f"    -> {r}")

        if finding.persistence_indicators:
            lines.append("")
            lines.append("--- Persistence ---")
            for p in finding.persistence_indicators:
                if p.flagged:
                    lines.append(f"  [{p.method}] {p.entry_name}")
                    for r in p.flag_reasons:
                        lines.append(f"    -> {r}")

        if finding.process.cmdline:
            lines.append("")
            lines.append("--- Command Line ---")
            lines.append(f"  {' '.join(finding.process.cmdline)}")

        self.content_label.configure(text="\n".join(lines))

    def clear(self) -> None:
        self.title_label.configure(text="Select a finding")
        self.content_label.configure(text="")
