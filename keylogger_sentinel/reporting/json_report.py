"""JSON report generator."""

from __future__ import annotations

import json
import os
import time
from typing import Any

from core.models import ScanResult


def generate_json_report(result: ScanResult, output_path: str) -> str:
    """Export scan results to a JSON file.

    Args:
        result: ScanResult to export.
        output_path: Destination file path.

    Returns:
        Absolute path of the written file.
    """
    data = result.to_dict()
    data["report_generated"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    data["tool"] = "Keylogger Detector"
    data["version"] = "1.0.0"

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    return os.path.abspath(output_path)
