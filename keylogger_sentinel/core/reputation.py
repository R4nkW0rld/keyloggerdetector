"""File reputation checker – SHA-256 hash lookup against known-bad lists."""

from __future__ import annotations

import hashlib
import os
from typing import Dict, List, Set

import yaml

from core.models import ProcessInfo


class ReputationChecker:
    """Computes SHA-256 hashes of executables and checks against known-bad lists.

    The checker is extensible: load hashes from YAML files or override
    with a custom lookup method.
    """

    def __init__(self) -> None:
        self._known_bad: Set[str] = set()
        self._cache: Dict[str, str] = {}  # path -> sha256

    def load_hash_file(self, path: str) -> int:
        """Load known-bad hashes from a YAML file.

        Expected YAML structure:
            hashes:
              - sha256: "abc123..."
                description: "Known keylogger"
              - sha256: "def456..."
                description: "Another bad hash"

        Returns:
            Number of hashes loaded.
        """
        if not os.path.isfile(path):
            return 0
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
            if data is None:
                return 0
            entries = data.get("hashes", []) if isinstance(data, dict) else []
            count = 0
            for entry in entries:
                h = entry.get("sha256", "").strip().lower()
                if h:
                    self._known_bad.add(h)
                    count += 1
            return count
        except (yaml.YAMLError, OSError, ValueError):
            return 0

    def add_hash(self, sha256: str) -> None:
        """Add a single hash to the known-bad set."""
        self._known_bad.add(sha256.strip().lower())

    def check(self, proc: ProcessInfo) -> tuple[bool, str]:
        """Check if a process executable matches a known-bad hash.

        Returns:
            (is_known_bad, sha256_hash)
        """
        sha256 = self.hash_file(proc.exe)
        if not sha256:
            return False, ""
        return sha256 in self._known_bad, sha256

    def hash_file(self, path: str) -> str:
        """Compute SHA-256 of a file. Returns empty string on failure."""
        if not path or not os.path.isfile(path):
            return ""

        # Cache hit
        if path in self._cache:
            return self._cache[path]

        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            digest = h.hexdigest()
            self._cache[path] = digest
            return digest
        except (OSError, PermissionError):
            return ""

    @property
    def known_bad_count(self) -> int:
        return len(self._known_bad)

    def clear_cache(self) -> None:
        self._cache.clear()
