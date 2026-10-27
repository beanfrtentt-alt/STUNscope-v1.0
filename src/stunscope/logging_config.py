"""Diagnostic logging shared by the CLI and the GUI.

A rotating file log is written to the STUNScope configuration directory
(``%APPDATA%\\STUNScope\\logs`` on Windows). Log files contain interface
names and diagnostics — never packet payloads or decoded addresses — and
can be removed at any time from the GUI Settings page ("Clear stored
capture data").
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from typing import Optional

from stunscope.config import logs_dir

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
LOG_MAX_BYTES = 1_000_000
LOG_BACKUP_COUNT = 3


def setup_logging(
    verbose: bool = False,
    log_to_file: bool = True,
    logger_name: str = "stunscope",
) -> logging.Logger:
    """Configure the application logger. Safe to call repeatedly.

    - ``verbose=True`` sets DEBUG level on the console; otherwise INFO.
    - ``log_to_file=True`` attaches a rotating file handler when the log
      directory is writable; failures to create the handler are ignored
      so logging never blocks the application from starting.
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if not logger.handlers:
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(console)

    if log_to_file and not any(
        isinstance(h, RotatingFileHandler) for h in logger.handlers
    ):
        try:
            directory = logs_dir()
            directory.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                directory / "stunscope.log",
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
            logger.addHandler(file_handler)
        except OSError:
            # Read-only media, locked profile, etc. Console logging still works.
            logger.debug("file logging disabled: log directory is not writable")

    level = logging.DEBUG if verbose else logging.INFO
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setLevel(level)
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a child logger, e.g. ``get_logger("capture")``."""
    if not name:
        return logging.getLogger("stunscope")
    if name.startswith("stunscope"):
        return logging.getLogger(name)
    return logging.getLogger(f"stunscope.{name}")
