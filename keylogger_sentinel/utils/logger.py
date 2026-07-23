"""Logging setup – rotating file logger with console output."""

from __future__ import annotations

import logging
import logging.handlers
import os
from typing import Optional


def setup_logger(
    name: str = "keylogger_sentinel",
    level: str = "INFO",
    log_file: str = "logs/detector.log",
    max_bytes: int = 5_242_880,
    backup_count: int = 3,
) -> logging.Logger:
    """Configure and return a logger with rotating file handler.

    Args:
        name: Logger name.
        level: Log level string (DEBUG, INFO, WARNING, ERROR).
        log_file: Path to log file.
        max_bytes: Max size per log file before rotation.
        backup_count: Number of backup log files to keep.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    # Prevent duplicate handlers on re-init
    if logger.handlers:
        return logger

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(numeric_level)
    console_fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    console.setFormatter(console_fmt)
    logger.addHandler(console)

    # Rotating file handler
    try:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        file_fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_fmt)
        logger.addHandler(file_handler)
    except OSError:
        logger.warning(f"Could not create log file at {log_file}")

    return logger


# Module-level logger
logger = setup_logger()
