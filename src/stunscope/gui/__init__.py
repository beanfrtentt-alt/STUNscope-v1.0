"""STUNScope GUI package (PySide6).

The desktop interface imports the shared engine from :mod:`stunscope`
(parser, filters, exporter, capture). PySide6 itself is imported only
inside GUI modules, so the CLI and the test suite work without it.
"""

from __future__ import annotations

__all__ = ["main"]
