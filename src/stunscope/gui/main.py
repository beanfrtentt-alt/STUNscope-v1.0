"""GUI entry point: ``python -m stunscope.gui`` or ``python -m stunscope gui``.

PySide6 is imported here (and only here) so the CLI and the test suite
work on machines without the GUI stack installed.
"""

from __future__ import annotations

import sys


def run() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:
        print(
            "error: PySide6 is not installed, so the GUI cannot start "
            f"({exc}).\n"
            "       Install it with:  pip install PySide6\n"
            "       or reinstall the full package: pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 2

    from stunscope import __version__
    from stunscope.gui.logging_bridge import install_logging_bridge
    from stunscope.gui.main_window import MainWindow
    from stunscope.gui.theme import apply_theme

    app = QApplication(sys.argv or ["stunscope"])
    app.setApplicationName("STUNScope")
    app.setApplicationVersion(__version__)
    apply_theme(app)
    install_logging_bridge()

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
