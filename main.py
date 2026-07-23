#!/usr/bin/env python3
"""Launcher for Keylogger Detector from the workspace root."""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.join(ROOT, "keylogger_sentinel")

if __name__ == "__main__":
    os.chdir(PROJECT_DIR)
    sys.exit(subprocess.call([sys.executable, "main.py", *sys.argv[1:]]))
