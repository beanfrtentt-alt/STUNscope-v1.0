"""Route Python logging records into a Qt message box visible to the user.

Keeps capture diagnostics discoverable in the GUI without a console
window. Only ERROR-level records from the ``stunscope`` logger trigger a
dialog; everything else goes to the rotating file as usual.
"""

from __future__ import annotations

import logging

from stunscope.logging_config import get_logger

logger = get_logger("gui.bridge")


class _QtLogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            from PySide6.QtWidgets import QMessageBox

            if record.levelno >= logging.ERROR and record.name.startswith("stunscope"):
                QMessageBox.critical(
                    None,
                    "STUNScope error",
                    record.getMessage(),
                )
        except Exception:  # pragma: no cover - never crash on logging
            self.handleError(record)


def install_logging_bridge() -> None:
    """Attach the Qt handler once per process."""
    stunscope_logger = logging.getLogger("stunscope")
    if any(isinstance(h, _QtLogHandler) for h in stunscope_logger.handlers):
        return
    handler = _QtLogHandler(level=logging.ERROR)
    stunscope_logger.addHandler(handler)
