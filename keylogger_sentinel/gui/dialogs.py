"""Dialog windows for Keylogger Sentinel."""

from __future__ import annotations

from typing import Any, Callable, Optional

try:
    import customtkinter as ctk
except ImportError:
    import tkinter as tk
    ctk = None


class ConfirmDialog:
    """Modal confirmation dialog for destructive actions."""

    def __init__(self, parent: Any, title: str, message: str,
                 on_confirm: Callable[[], None] | None = None) -> None:
        self._parent = parent
        self._on_confirm = on_confirm
        self._result = False

        if ctk:
            self._dialog = ctk.CTkToplevel(parent)
        else:
            self._dialog = tk.Toplevel(parent)

        self._dialog.title(title)
        self._dialog.geometry("400x200")
        self._dialog.transient(parent)
        self._dialog.grab_set()

        if ctk:
            msg = ctk.CTkLabel(self._dialog, text=message, wraplength=350, font=ctk.CTkFont(size=13))
        else:
            msg = tk.Label(self._dialog, text=message, wraplength=350, font=("Arial", 11))
        msg.pack(pady=20, padx=20)

        btn_frame = ctk.CTkFrame(self._dialog, fg_color="transparent") if ctk else tk.Frame(self._dialog)
        btn_frame.pack(pady=10)

        if ctk:
            cancel_btn = ctk.CTkButton(btn_frame, text="Cancel", width=100,
                                       command=self._cancel, fg_color="#95a5a6")
            confirm_btn = ctk.CTkButton(btn_frame, text="Confirm", width=100,
                                        command=self._confirm, fg_color="#e74c3c")
        else:
            cancel_btn = tk.Button(btn_frame, text="Cancel", width=10,
                                   command=self._cancel, bg="#95a5a6")
            confirm_btn = tk.Button(btn_frame, text="Confirm", width=10,
                                    command=self._confirm, bg="#e74c3c")

        cancel_btn.pack(side="left", padx=10)
        confirm_btn.pack(side="left", padx=10)

    def _cancel(self) -> None:
        self._result = False
        self._dialog.destroy()

    def _confirm(self) -> None:
        self._result = True
        if self._on_confirm:
            self._on_confirm()
        self._dialog.destroy()

    @property
    def result(self) -> bool:
        return self._result


class WhitelistDialog:
    """Dialog for adding a process to the whitelist."""

    def __init__(self, parent: Any, pid: int = 0, name: str = "",
                 on_submit: Callable[[int, str], None] | None = None) -> None:
        self._parent = parent
        self._on_submit = on_submit
        self._result_pid = pid
        self._result_name = name

        if ctk:
            self._dialog = ctk.CTkToplevel(parent)
        else:
            self._dialog = tk.Toplevel(parent)

        self._dialog.title("Add to Whitelist")
        self._dialog.geometry("350x200")
        self._dialog.transient(parent)
        self._dialog.grab_set()

        if ctk:
            ctk.CTkLabel(self._dialog, text="PID:").pack(pady=(15, 2))
            self._pid_entry = ctk.CTkEntry(self._dialog, width=250)
            self._pid_entry.insert(0, str(pid))
            self._pid_entry.pack(pady=2)

            ctk.CTkLabel(self._dialog, text="Process Name:").pack(pady=(10, 2))
            self._name_entry = ctk.CTkEntry(self._dialog, width=250)
            self._name_entry.insert(0, name)
            self._name_entry.pack(pady=2)

            btn_frame = ctk.CTkFrame(self._dialog, fg_color="transparent")
            btn_frame.pack(pady=10)
            ctk.CTkButton(btn_frame, text="Cancel", width=80,
                           command=self._dialog.destroy,
                           fg_color="#95a5a6").pack(side="left", padx=5)
            ctk.CTkButton(btn_frame, text="Add", width=80,
                           command=self._submit,
                           fg_color="#2ecc71").pack(side="left", padx=5)
        else:
            tk.Label(self._dialog, text="PID:").pack(pady=(15, 2))
            self._pid_entry = tk.Entry(self._dialog, width=30)
            self._pid_entry.insert(0, str(pid))
            self._pid_entry.pack(pady=2)

            tk.Label(self._dialog, text="Process Name:").pack(pady=(10, 2))
            self._name_entry = tk.Entry(self._dialog, width=30)
            self._name_entry.insert(0, name)
            self._name_entry.pack(pady=2)

            btn_frame = tk.Frame(self._dialog)
            btn_frame.pack(pady=10)
            tk.Button(btn_frame, text="Cancel", command=self._dialog.destroy).pack(side="left", padx=5)
            tk.Button(btn_frame, text="Add", command=self._submit).pack(side="left", padx=5)

    def _submit(self) -> None:
        try:
            self._result_pid = int(self._pid_entry.get())
        except ValueError:
            self._result_pid = 0
        self._result_name = self._name_entry.get()
        if self._on_submit:
            self._on_submit(self._result_pid, self._result_name)
        self._dialog.destroy()


class ExportDialog:
    """Dialog for choosing export format and destination."""

    def __init__(self, parent: Any, output_dir: str = "reports",
                 on_export: Callable[[str, str], None] | None = None) -> None:
        self._parent = parent
        self._on_export = on_export
        self._format = "json"
        self._output_dir = output_dir

        if ctk:
            self._dialog = ctk.CTkToplevel(parent)
        else:
            self._dialog = tk.Toplevel(parent)

        self._dialog.title("Export Report")
        self._dialog.geometry("350x220")
        self._dialog.transient(parent)
        self._dialog.grab_set()

        if ctk:
            ctk.CTkLabel(self._dialog, text="Export Format:").pack(pady=(15, 5))
            self._format_var = ctk.StringVar(value="json")
            formats = ctk.CTkSegmentedButton(
                self._dialog, values=["json", "csv", "html"],
                variable=self._format_var,
            )
            formats.pack(pady=5)

            ctk.CTkLabel(self._dialog, text="Output Directory:").pack(pady=(10, 2))
            self._dir_entry = ctk.CTkEntry(self._dialog, width=250)
            self._dir_entry.insert(0, output_dir)
            self._dir_entry.pack(pady=2)

            btn_frame = ctk.CTkFrame(self._dialog, fg_color="transparent")
            btn_frame.pack(pady=10)
            ctk.CTkButton(btn_frame, text="Cancel", width=80,
                           command=self._dialog.destroy,
                           fg_color="#95a5a6").pack(side="left", padx=5)
            ctk.CTkButton(btn_frame, text="Export", width=80,
                           command=self._submit,
                           fg_color="#3498db").pack(side="left", padx=5)
        else:
            tk.Label(self._dialog, text="Export Format:").pack(pady=(15, 5))
            self._format_var = tk.StringVar(value="json")
            for fmt in ("json", "csv", "html"):
                tk.Radiobutton(self._dialog, text=fmt, variable=self._format_var,
                               value=fmt).pack()
            tk.Label(self._dialog, text="Output Directory:").pack(pady=(10, 2))
            self._dir_entry = tk.Entry(self._dialog, width=30)
            self._dir_entry.insert(0, output_dir)
            self._dir_entry.pack(pady=2)
            tk.Button(self._dialog, text="Export", command=self._submit).pack(pady=10)

    def _submit(self) -> None:
        self._format = self._format_var.get()
        self._output_dir = self._dir_entry.get()
        if self._on_export:
            self._on_export(self._format, self._output_dir)
        self._dialog.destroy()
