"""Configuration loader – reads YAML config files."""

from __future__ import annotations

import os
from typing import Any, Dict

import yaml


class ConfigManager:
    """Manages application configuration from YAML files.

    Provides a single source of truth for thresholds, whitelists,
    keyword lists, and other tunable parameters.
    """

    DEFAULT_CONFIG: Dict[str, Any] = {
        "scan_interval_seconds": 30,
        "auto_refresh": True,
        "min_connection_duration": 300,
        "weights": {
            "keyword_match": 15,
            "suspicious_path": 20,
            "suspicious_parent": 10,
            "network_connection": 25,
            "registry_autostart": 30,
            "known_bad_hash": 40,
            "system_hooks": 35,
            "hidden_execution": 15,
            "persistence": 20,
        },
        "thresholds": {
            "low": 0,
            "medium": 26,
            "high": 51,
            "critical": 76,
        },
        "known_bad_hashes_file": "known_bad_hashes.yaml",
        "whitelist": {
            "pids": [],
            "names": [],
            "paths": [],
        },
        "logging": {
            "level": "INFO",
            "max_bytes": 5_242_880,
            "backup_count": 3,
            "log_file": "logs/detector.log",
        },
        "export": {
            "default_format": "json",
            "output_dir": "reports",
        },
        "notifications": {
            "enabled": True,
            "min_severity": "high",
        },
    }

    def __init__(self, config_path: str | None = None) -> None:
        self._data: Dict[str, Any] = dict(self.DEFAULT_CONFIG)
        self._config_path = config_path
        if config_path and os.path.isfile(config_path):
            self._load(config_path)

    def _load(self, path: str) -> None:
        """Load and merge config from a YAML file."""
        try:
            with open(path, "r") as f:
                file_data = yaml.safe_load(f)
            if isinstance(file_data, dict):
                self._deep_merge(self._data, file_data)
        except (yaml.YAMLError, OSError) as e:
            print(f"Warning: Could not load config from {path}: {e}")

    def _deep_merge(self, base: Dict, override: Dict) -> None:
        """Deep merge override into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value using dot notation. E.g. get('weights.keyword_match')."""
        keys = key.split(".")
        current = self._data
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        return current

    def set(self, key: str, value: Any) -> None:
        """Set a config value using dot notation."""
        keys = key.split(".")
        current = self._data
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value

    @property
    def data(self) -> Dict[str, Any]:
        """Return the full config dict."""
        return self._data

    @property
    def whitelist(self) -> Dict[str, Any]:
        return self._data.get("whitelist", {})

    @property
    def weights(self) -> Dict[str, int]:
        return self._data.get("weights", {})

    @property
    def thresholds(self) -> Dict[str, int]:
        return self._data.get("thresholds", {})

    def save(self, path: str | None = None) -> None:
        """Save current config to a YAML file."""
        target = path or self._config_path
        if not target:
            return
        try:
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            with open(target, "w") as f:
                yaml.dump(self._data, f, default_flow_style=False, sort_keys=False)
        except OSError as e:
            print(f"Error saving config: {e}")
