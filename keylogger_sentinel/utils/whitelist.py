"""Whitelist manager – manages process whitelisting to reduce false positives."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Set

import yaml


class WhitelistManager:
    """Manages whitelisted PIDs, process names, and executable paths.

    Whitelisted processes are excluded from scanning to reduce false
    positives and improve performance.
    """

    def __init__(self) -> None:
        self._pids: Set[int] = set()
        self._names: Set[str] = set()
        self._paths: Set[str] = set()

    def load_from_config(self, wl_config: Dict[str, Any]) -> None:
        """Load whitelist from a config dict."""
        self._pids = set(wl_config.get("pids", []))
        self._names = {n.lower() for n in wl_config.get("names", [])}
        self._paths = {p.lower() for p in wl_config.get("paths", [])}

    def load_from_file(self, path: str) -> int:
        """Load whitelist from a YAML or JSON file.

        Returns:
            Number of entries loaded.
        """
        if not os.path.isfile(path):
            return 0

        try:
            with open(path, "r") as f:
                if path.endswith((".yaml", ".yml")):
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
        except (yaml.YAMLError, json.JSONDecodeError, OSError):
            return 0

        if not isinstance(data, dict):
            return 0

        count = 0
        for pid in data.get("pids", []):
            self._pids.add(int(pid))
            count += 1
        for name in data.get("names", []):
            self._names.add(name.lower())
            count += 1
        for path_entry in data.get("paths", []):
            self._paths.add(path_entry.lower())
            count += 1
        return count

    def add_pid(self, pid: int) -> None:
        self._pids.add(pid)

    def add_name(self, name: str) -> None:
        self._names.add(name.lower())

    def add_path(self, path: str) -> None:
        self._paths.add(path.lower())

    def remove_pid(self, pid: int) -> None:
        self._pids.discard(pid)

    def remove_name(self, name: str) -> None:
        self._names.discard(name.lower())

    def is_whitelisted(self, pid: int = 0, name: str = "", exe_path: str = "") -> bool:
        """Check if a process matches any whitelist entry."""
        if pid and pid in self._pids:
            return True
        if name and name.lower() in self._names:
            return True
        if exe_path and exe_path.lower() in self._paths:
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pids": sorted(self._pids),
            "names": sorted(self._names),
            "paths": sorted(self._paths),
        }

    def save(self, path: str) -> None:
        """Save current whitelist to a file."""
        data = self.to_dict()
        try:
            with open(path, "w") as f:
                if path.endswith((".yaml", ".yml")):
                    yaml.dump(data, f, default_flow_style=False)
                else:
                    json.dump(data, f, indent=2)
        except OSError:
            pass

    @property
    def total_count(self) -> int:
        return len(self._pids) + len(self._names) + len(self._paths)

    def clear(self) -> None:
        self._pids.clear()
        self._names.clear()
        self._paths.clear()
