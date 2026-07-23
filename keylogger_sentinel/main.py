#!/usr/bin/env python3
"""Keylogger Detector – Defensive keylogger detection tool.

This tool detects suspicious keylogger-like activity on a user's own
machine. It NEVER captures keystrokes, records input, or exfiltrates
data. It is strictly a read-only defensive scanner.

Usage:
    python main.py                  # Launch GUI
    python main.py --cli            # Run CLI scan
    python main.py --config FILE    # Use custom config
"""

from __future__ import annotations

import argparse
import os
import sys

# Ensure the package root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_gui(config_path: str | None = None) -> None:
    """Launch the PySide6 GUI application."""
    from utils.logger import logger

    logger.info("Starting Keylogger Detector GUI (PySide6)")

    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtGui import QFont
        from PySide6.QtCore import Qt
        from ui.main_window import MainWindow

        app = QApplication(sys.argv)
        app.setApplicationName("Keylogger Detector")
        app.setApplicationVersion("1.0.0")

        font = QFont("Inter, Segoe UI, SF Pro Display, Roboto, Helvetica Neue, Arial", 13)
        app.setFont(font)

        window = MainWindow(config_path=config_path)
        window.show()

        sys.exit(app.exec())
    except ImportError as e:
        print(f"PySide6 dependencies missing: {e}")
        print("Install with: pip install PySide6")
        sys.exit(1)
    except Exception as e:
        logger.error(f"GUI failed to start: {e}")
        raise


def run_gui_legacy(config_path: str | None = None) -> None:
    """Launch the legacy CustomTkinter GUI application."""
    from utils.config import ConfigManager
    from utils.logger import logger

    logger.info("Starting Keylogger Detector GUI (Legacy)")

    try:
        from gui.app import DetectorApp
        app = DetectorApp()
        app.run()
    except ImportError as e:
        print(f"GUI dependencies missing: {e}")
        print("Install with: pip install customtkinter")
        sys.exit(1)
    except Exception as e:
        logger.error(f"GUI failed to start: {e}")
        raise


def run_cli(config_path: str | None = None) -> None:
    """Run a single CLI scan and print results."""
    from utils.config import ConfigManager
    from utils.logger import logger
    from core.detector import KeyloggerDetector
    from reporting.json_report import generate_json_report
    from reporting.csv_report import generate_csv_report
    from reporting.html_report import generate_html_report

    config = ConfigManager(config_path)
    detector = KeyloggerDetector(config.data)

    print("=" * 60)
    print("  Keylogger Detector - CLI Scan")
    print("=" * 60)
    print()

    result = detector.scan()

    print(f"Platform:           {result.platform}")
    print(f"Total processes:    {result.total_processes}")
    print(f"Scanned:            {result.scanned_processes}")
    print(f"Duration:           {result.scan_duration:.2f}s")
    print(f"Findings:           {len(result.findings)}")
    print()

    if not result.findings:
        print("  No suspicious processes detected.")
    else:
        print(f"  {'PID':>7}  {'Score':>5}  {'Severity':<10}  {'Name':<30}  {'Reasons'}")
        print(f"  {'-'*7}  {'-'*5}  {'-'*10}  {'-'*30}  {'-'*40}")
        for f in result.findings:
            reasons_str = "; ".join(f.reasons[:2])
            print(
                f"  {f.process.pid:>7}  {f.risk_score:>5}  "
                f"{f.severity.label:<10}  {f.process.name:<30}  "
                f"{reasons_str}"
            )

    # Export reports
    os.makedirs("reports", exist_ok=True)
    json_path = generate_json_report(result, "reports/scan_result.json")
    csv_path = generate_csv_report(result, "reports/scan_result.csv")
    html_path = generate_html_report(result, "reports/scan_result.html")
    print()
    print(f"  Reports exported:")
    print(f"    JSON: {json_path}")
    print(f"    CSV:  {csv_path}")
    print(f"    HTML: {html_path}")
    print()

    if result.scan_errors:
        print("  Errors:")
        for err in result.scan_errors:
            print(f"    - {err}")


def main() -> None:
    """Parse arguments and launch the appropriate mode."""
    parser = argparse.ArgumentParser(
        description="Keylogger Detector - Defensive Keylogger Detection Tool",
        epilog="IMPORTANT: This tool NEVER captures keystrokes or exfiltrates data.",
    )
    parser.add_argument(
        "--cli", action="store_true",
        help="Run in CLI mode (single scan, no GUI)",
    )
    parser.add_argument(
        "--legacy", action="store_true",
        help="Use legacy CustomTkinter GUI instead of PySide6",
    )
    parser.add_argument(
        "--config", type=str, default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "--version", action="version", version="Keylogger Detector 1.0.0",
    )

    args = parser.parse_args()

    if args.cli:
        run_cli(args.config)
    elif args.legacy:
        run_gui_legacy(args.config)
    else:
        run_gui(args.config)


if __name__ == "__main__":
    main()
