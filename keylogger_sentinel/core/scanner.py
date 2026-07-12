"""Process scanner – enumerates and inspects running processes."""

from __future__ import annotations

import os
import platform
import re
import sys
from typing import Dict, List, Set

import psutil

from core.models import ProcessInfo


class ProcessScanner:
    """Enumerates processes and collects metadata for analysis.

    This scanner is strictly read-only. It never injects into or modifies
    any process. It reads public psutil APIs only.
    """

    # Keyword patterns commonly associated with keyloggers or input hooks.
    # These are matched as whole words (with word boundaries) to avoid
    # false positives from common process names and paths.
    KEYWORD_PATTERNS: List[str] = [
        "keylog", "key_log", "input_hook", "hookproc",
        "clipboard_capture", "clipboard_spy",
        "setwindowshook", "setwindowshookex",
        "getasynckeystate", "getkeystate", "getforegroundwindow",
        "autohotkey", "pynput", "input_events", "rawinput",
        "usbkey", "keystroke_recorder", "keyrecorder",
    ]

    # Directories that indicate dropped/suspicious binaries
    SUSPICIOUS_PATHS: List[str] = [
        "appdata\\local\\temp",
        "appdata\\local\\microsoft\\windows\\ineteil",
        "downloads",
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "windows\\system32\\config\\systemprofile",
    ]

    # Known system process names that should not be flagged
    KNOWN_SYSTEM_NAMES: Set[str] = {
        "system", "system idle process", "registry", "smss.exe",
        "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
        "svchost.exe", "winlogon.exe", "dwm.exe", "explorer.exe",
        "python", "python3", "kernel_task", "launchd", "systemd",
        "init", "kthreadd", "sshd", "cron", "dbus-daemon",
        "dbus-launch", "NetworkManager", "polkitd", "rtkit-daemon",
        "accounts-daemon", "power-profiles-daemon", "ModemManager",
        "smartd", "rsyslogd", "tor", "at-spi-bus-launcher",
        "gnome-keyring-daemon", "gcr-ssh-agent", "ssh-agent",
        "gnome-session-ctl", "ibus-daemon", "gsd-datetime",
        "gsd-keyboard", "gsd-disk-utility-notify", "goa-daemon",
        "ibus-dconf", "xdg-desktop-portal", "xdg-document-portal",
        "xdg-desktop-portal-gnome", "xdg-desktop-portal-gtk",
        "gvfsd-dnssd", "speech-dispatcher", "sd_espeak-ng",
        "sd_dummy", "localsearch-3", "chrome_crashpad_handler",
        "Xwayland", "ibus-extension-gtk3",
        # Firefox subprocesses
        "Socket Process", "WebExtensions", "Utility Process",
        "Isolated Web Co",
    }

    # Suspicious parent-child relationships
    SUSPICIOUS_PARENTS: Dict[str, List[str]] = {
        "powershell.exe": ["cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe"],
        "cmd.exe": ["wscript.exe", "mshta.exe", "rundll32.exe"],
        "wscript.exe": ["outlook.exe", "winword.exe", "excel.exe"],
        "mshta.exe": ["outlook.exe", "winword.exe"],
        "rundll32.exe": ["wscript.exe", "mshta.exe"],
    }

    def __init__(self) -> None:
        self._platform = platform.system().lower()

    def scan(self) -> List[ProcessInfo]:
        """Enumerate all visible processes and return their info."""
        processes: List[ProcessInfo] = []
        for proc in psutil.process_iter(["pid"]):
            try:
                info = self._collect_info(proc)
                if info is not None:
                    processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return processes

    def _collect_info(self, proc: psutil.Process) -> ProcessInfo | None:
        """Collect detailed info for a single process."""
        try:
            pid = proc.pid
            name = proc.name()
            exe = ""
            cmdline: List[str] = []
            cwd = ""
            username = ""
            cpu = 0.0
            mem = 0.0
            ppid = 0
            parent_name = ""
            create_time = 0.0
            num_threads = 0
            status = ""

            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except Exception:
                pass

            try:
                cmdline = proc.cmdline()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass

            try:
                cwd = proc.cwd()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass

            try:
                username = proc.username()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass

            try:
                cpu = proc.cpu_percent(interval=0.0)
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass

            try:
                mem = proc.memory_info().rss / (1024 * 1024)
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass

            try:
                ppid = proc.ppid()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass

            try:
                parent = proc.parent()
                if parent is not None:
                    parent_name = parent.name()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass

            try:
                create_time = proc.create_time()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass

            try:
                num_threads = proc.num_threads()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass

            try:
                status = proc.status()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass

            return ProcessInfo(
                pid=pid,
                name=name,
                exe=exe,
                cmdline=cmdline,
                cwd=cwd,
                username=username,
                cpu_percent=cpu,
                memory_mb=round(mem, 2),
                parent_pid=ppid,
                parent_name=parent_name,
                create_time=create_time,
                num_threads=num_threads,
                status=status,
                is_hidden=self._is_hidden(name, exe),
                is_system=self._is_system(name),
                platform=self._platform,
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def _is_hidden(self, name: str, exe: str) -> bool:
        """Detect hidden processes (e.g. prefixed with null bytes on Linux)."""
        if name.startswith(("\x00", " ")):
            return True
        if self._platform == "linux" and exe:
            basename = os.path.basename(exe)
            if basename.startswith(".") and basename != ".":
                return True
        if self._platform == "windows" and exe:
            if "appdata" in exe.lower() and "windows" not in exe.lower():
                return True
        return False

    def _is_system(self, name: str) -> bool:
        """Check if the process is a known system process."""
        return name.lower() in self.KNOWN_SYSTEM_NAMES

    @classmethod
    def has_suspicious_keywords(cls, proc: ProcessInfo) -> List[str]:
        """Check process name and cmdline for suspicious keywords."""
        hits: List[str] = []
        text = " ".join([proc.name] + proc.cmdline + [proc.exe, proc.cwd]).lower()
        for kw in cls.KEYWORD_PATTERNS:
            if re.search(r'(?<![a-z])' + re.escape(kw) + r'(?![a-z])', text):
                hits.append(kw)
        return hits

    @classmethod
    def has_suspicious_path(cls, proc: ProcessInfo) -> List[str]:
        """Check if the executable or cwd lies in suspicious directories."""
        hits: List[str] = []
        check_str = (proc.exe + " " + proc.cwd).lower()
        for sp in cls.SUSPICIOUS_PATHS:
            if sp in check_str:
                hits.append(sp)
        return hits

    @classmethod
    def has_suspicious_parent(cls, proc: ProcessInfo) -> str | None:
        """Check for suspicious parent-child process relationships."""
        name_lower = proc.name.lower()
        parent_lower = proc.parent_name.lower()
        if name_lower in cls.SUSPICIOUS_PARENTS:
            if parent_lower in cls.SUSPICIOUS_PARENTS[name_lower]:
                return f"{proc.name} spawned by {proc.parent_name}"
        return None

    @classmethod
    def has_hidden_execution(cls, proc: ProcessInfo) -> List[str]:
        """Detect hidden execution flags."""
        reasons: List[str] = []
        if proc.is_hidden:
            reasons.append("Process appears hidden (null prefix or dotfile)")
        flags = " ".join(proc.cmdline).lower()
        hidden_flags = ["--hidden", "--stealth", "/silent", "-silent"]
        for flag in hidden_flags:
            if flag in flags:
                reasons.append(f"Suspicious flag: {flag}")
        return reasons

    @classmethod
    def has_system_hooks(cls, proc: ProcessInfo) -> List[str]:
        """Detect likely system hooks by inspecting cmdline for hook APIs."""
        reasons: List[str] = []
        flags = " ".join(proc.cmdline).lower()
        hook_terms = [
            "setwindowshookex", "setwindowshook", "getasynckeystate",
            "getkeystate", "registerhotkey",
        ]
        for term in hook_terms:
            if term in flags:
                reasons.append(f"Hook API reference: {term}")
        return reasons
