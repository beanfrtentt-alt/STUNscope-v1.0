"""Allows ``python -m stunscope.gui``."""

from __future__ import annotations

import sys

if __name__ == "__main__":
    from stunscope.gui.main import run

    sys.exit(run())
