"""Persistence scanner – detects autorun / persistence mechanisms."""

from __future__ import annotations

import glob
import os
import platform
import subprocess
from typing import Dict, List

from core.models import PersistenceIndicator


class PersistenceScanner:
    """Checks for persistence mechanisms across platforms.

    All checks are read-only. The scanner never modifies registry keys,
    startup folders, or scheduled tasks.
    """

    # Common Windows autorun registry locations
    WIN_RUN_KEYS: List[Dict[str, str]] = [
        {"hive": "HKCU", "path": r"Software\Microsoft\Windows\CurrentVersion\Run"},
        {"hive": "HKCU", "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce"},
        {"hive": "HKLM", "path": r"Software\Microsoft\Windows\CurrentVersion\Run"},
        {"hive": "HKLM", "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce"},
        {"hive": "HKLM", "path": r"Software\Microsoft\Windows\CurrentVersion\RunServices"},
        {"hive": "HKLM", "path": r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"},
        {"hive": "HKCU", "path": r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"},
        {"hive": "HKCU", "path": r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"},
        {"hive": "HKLM", "path": r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"},
        {"hive": "HKLM", "path": r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"},
        {"hive": "HKCU", "path": r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"},
    ]

    WIN_RUNONCE_DIRS = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]

    # Linux/macOS persistence locations
    LINUX_SYSTEMD_DIRS = [
        "/etc/systemd/system",
        os.path.expanduser("~/.config/systemd/user"),
    ]
    LINUX_CRONTAB_PATHS = [
        "/etc/crontab",
        "/var/spool/cron/crontabs",
    ]
    MACOS_LAUNCH_AGENTS = [
        os.path.expanduser("~/Library/LaunchAgents"),
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
    ]
    LINUX_AUTOSTART_DIRS = [
        os.path.expanduser("~/.config/autostart"),
        "/etc/xdg/autostart",
    ]

    def __init__(self) -> None:
        self._platform = platform.system().lower()

    def scan(self) -> List[PersistenceIndicator]:
        """Run all persistence checks for the current platform."""
        indicators: List[PersistenceIndicator] = []
        if self._platform == "windows":
            indicators.extend(self._check_windows_registry())
            indicators.extend(self._check_windows_startup())
            indicators.extend(self._check_windows_tasks())
        elif self._platform == "darwin":
            indicators.extend(self._check_macos_launch_agents())
            indicators.extend(self._check_linux_autostart())
        else:
            indicators.extend(self._check_linux_systemd())
            indicators.extend(self._check_linux_crontab())
            indicators.extend(self._check_linux_autostart())
        return indicators

    def _check_windows_registry(self) -> List[PersistenceIndicator]:
        """Read Windows Registry autorun keys via reg query."""
        indicators: List[PersistenceIndicator] = []
        for entry in self.WIN_RUN_KEYS:
            try:
                cmd = [
                    "reg", "query",
                    f"{entry['hive']}\\{entry['path']}",
                    "/s", "/f", "", "/d", "/c",
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split("\n")
                    current_key = ""
                    for line in lines:
                        line_s = line.strip()
                        if line_s.startswith(entry["hive"]):
                            current_key = line_s
                        elif "=" in line_s or "(Default)" in line_s:
                            parts = line_s.split("=", 1) if "=" in line_s else ["(Default)", line_s]
                            val = parts[1].strip() if len(parts) > 1 else line_s
                            flag_reasons = self._flag_persistence_value(val)
                            indicators.append(PersistenceIndicator(
                                method="Registry AutoRun",
                                location=f"{entry['hive']}\\{entry['path']}",
                                entry_name=current_key or entry["path"],
                                command=val,
                                flagged=len(flag_reasons) > 0,
                                flag_reasons=flag_reasons,
                            ))
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
        return indicators

    def _check_windows_startup(self) -> List[PersistenceIndicator]:
        """Check Windows startup folders."""
        indicators: List[PersistenceIndicator] = []
        for folder in self.WIN_RUNONCE_DIRS:
            if not os.path.isdir(folder):
                continue
            for item in glob.glob(os.path.join(folder, "*")):
                if os.path.isfile(item):
                    flag_reasons = self._flag_startup_item(item)
                    indicators.append(PersistenceIndicator(
                        method="Startup Folder",
                        location=folder,
                        entry_name=os.path.basename(item),
                        command=item,
                        flagged=len(flag_reasons) > 0,
                        flag_reasons=flag_reasons,
                    ))
        return indicators

    def _check_windows_tasks(self) -> List[PersistenceIndicator]:
        """Check Windows Task Scheduler for suspicious tasks."""
        indicators: List[PersistenceIndicator] = []
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/nh"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    line_s = line.strip().strip('"')
                    if not line_s:
                        continue
                    parts = line_s.split('","')
                    task_name = parts[0].strip('"') if parts else "unknown"
                    task_action = parts[1].strip('"') if len(parts) > 1 else ""
                    flag_reasons = self._flag_task(task_name, task_action)
                    indicators.append(PersistenceIndicator(
                        method="Task Scheduler",
                        location="Task Scheduler",
                        entry_name=task_name,
                        command=task_action,
                        flagged=len(flag_reasons) > 0,
                        flag_reasons=flag_reasons,
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return indicators

    def _check_macos_launch_agents(self) -> List[PersistenceIndicator]:
        """Check macOS LaunchAgents/LaunchDaemons."""
        indicators: List[PersistenceIndicator] = []
        for folder in self.MACOS_LAUNCH_AGENTS:
            if not os.path.isdir(folder):
                continue
            for plist in glob.glob(os.path.join(folder, "*.plist")):
                try:
                    with open(plist, "r") as f:
                        content = f.read()
                    flag_reasons = self._flag_plist(plist, content)
                    indicators.append(PersistenceIndicator(
                        method="LaunchAgent/Daemon",
                        location=folder,
                        entry_name=os.path.basename(plist),
                        command=content[:200],
                        flagged=len(flag_reasons) > 0,
                        flag_reasons=flag_reasons,
                    ))
                except (OSError, PermissionError):
                    continue
        return indicators

    def _check_linux_systemd(self) -> List[PersistenceIndicator]:
        """Check Linux systemd unit files."""
        indicators: List[PersistenceIndicator] = []
        for folder in self.LINUX_SYSTEMD_DIRS:
            if not os.path.isdir(folder):
                continue
            for unit in glob.glob(os.path.join(folder, "*.service")):
                try:
                    with open(unit, "r") as f:
                        content = f.read()
                    flag_reasons = self._flag_systemd_unit(content)
                    indicators.append(PersistenceIndicator(
                        method="Systemd Service",
                        location=folder,
                        entry_name=os.path.basename(unit),
                        command=content[:200],
                        flagged=len(flag_reasons) > 0,
                        flag_reasons=flag_reasons,
                    ))
                except (OSError, PermissionError):
                    continue
        return indicators

    def _check_linux_crontab(self) -> List[PersistenceIndicator]:
        """Check Linux crontab entries."""
        indicators: List[PersistenceIndicator] = []
        # System crontab
        for path in self.LINUX_CRONTAB_PATHS:
            if os.path.isfile(path):
                try:
                    with open(path, "r") as f:
                        for line in f:
                            line_s = line.strip()
                            if not line_s or line_s.startswith("#"):
                                continue
                            flag_reasons = self._flag_cron_entry(line_s)
                            indicators.append(PersistenceIndicator(
                                method="Crontab",
                                location=path,
                                entry_name="cron_entry",
                                command=line_s,
                                flagged=len(flag_reasons) > 0,
                                flag_reasons=flag_reasons,
                            ))
                except (OSError, PermissionError):
                    continue
        # User crontab
        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    line_s = line.strip()
                    if not line_s or line_s.startswith("#"):
                        continue
                    flag_reasons = self._flag_cron_entry(line_s)
                    indicators.append(PersistenceIndicator(
                        method="User Crontab",
                        location="~/.crontab",
                        entry_name="user_cron",
                        command=line_s,
                        flagged=len(flag_reasons) > 0,
                        flag_reasons=flag_reasons,
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return indicators

    def _check_linux_autostart(self) -> List[PersistenceIndicator]:
        """Check Linux autostart .desktop files."""
        indicators: List[PersistenceIndicator] = []
        for folder in self.LINUX_AUTOSTART_DIRS:
            if not os.path.isdir(folder):
                continue
            for desktop in glob.glob(os.path.join(folder, "*.desktop")):
                try:
                    with open(desktop, "r") as f:
                        content = f.read()
                    flag_reasons = self._flag_desktop_autostart(content)
                    indicators.append(PersistenceIndicator(
                        method="Autostart Desktop Entry",
                        location=folder,
                        entry_name=os.path.basename(desktop),
                        command=content[:200],
                        flagged=len(flag_reasons) > 0,
                        flag_reasons=flag_reasons,
                    ))
                except (OSError, PermissionError):
                    continue
        return indicators

    def _flag_persistence_value(self, value: str) -> List[str]:
        """Flag suspicious registry persistence values."""
        reasons: List[str] = []
        value_lower = value.lower()
        suspicious_terms = [
            "powershell", "cmd.exe", "wscript", "mshta", "rundll32",
            "regsvr32", "bitsadmin", "certutil", "wget", "curl",
            "http://", "https://", "temp\\", "appdata",
            "base64", "-enc ", "-e ", "downloadstring",
            "invoke-expression", "iex", "invoke-restmethod",
        ]
        for term in suspicious_terms:
            if term in value_lower:
                reasons.append(f"Suspicious persistence value: {term}")
        return reasons

    def _flag_startup_item(self, path: str) -> List[str]:
        """Flag suspicious startup folder items."""
        reasons: List[str] = []
        ext = os.path.splitext(path)[1].lower()
        if ext in (".vbs", ".js", ".ps1", ".bat", ".cmd", ".hta"):
            reasons.append(f"Script in startup folder: {ext}")
        return reasons

    def _flag_task(self, name: str, action: str) -> List[str]:
        """Flag suspicious scheduled tasks."""
        reasons: List[str] = []
        combined = (name + " " + action).lower()
        if "powershell" in combined or "cmd" in combined:
            reasons.append("Task runs shell command")
        if "http" in combined or "download" in combined:
            reasons.append("Task downloads content")
        return reasons

    def _flag_plist(self, path: str, content: str) -> List[str]:
        """Flag suspicious LaunchAgent/Daemon plists."""
        reasons: List[str] = []
        content_lower = content.lower()
        if "keepalive" in content_lower:
            reasons.append("Plist has KeepAlive (auto-restart)")
        if "http" in content_lower or "curl" in content_lower:
            reasons.append("Plist references network")
        return reasons

    def _flag_systemd_unit(self, content: str) -> List[str]:
        """Flag suspicious systemd units."""
        reasons: List[str] = []
        content_lower = content.lower()
        if "type=oneshot" not in content_lower and "execstart" in content_lower:
            if any(s in content_lower for s in ["http", "curl", "wget"]):
                reasons.append("Systemd unit downloads content")
        return reasons

    def _flag_cron_entry(self, entry: str) -> List[str]:
        """Flag suspicious crontab entries."""
        reasons: List[str] = []
        entry_lower = entry.lower()
        if "http" in entry_lower or "curl" in entry_lower or "wget" in entry_lower:
            reasons.append("Cron entry downloads content")
        if "/tmp/" in entry_lower or "/dev/shm/" in entry_lower:
            reasons.append("Cron runs from temp directory")
        return reasons

    def _flag_desktop_autostart(self, content: str) -> List[str]:
        """Flag suspicious .desktop autostart files."""
        reasons: List[str] = []
        content_lower = content.lower()
        if "http" in content_lower or "curl" in content_lower:
            reasons.append("Autostart entry downloads content")
        return reasons
