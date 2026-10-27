"""Entry point for ``python -m stunscope`` (runs the CLI)."""

from __future__ import annotations

import sys

from stunscope.cli import main

if __name__ == "__main__":
    sys.exit(main())
