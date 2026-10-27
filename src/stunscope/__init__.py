"""STUNScope — a STUN (RFC 8489) packet analyzer with a CLI and a desktop GUI.

STUNScope is intended for analyzing STUN traffic on networks you own or are
explicitly authorized to test. It ships a single shared protocol engine that
both the command-line interface and the PySide6 desktop interface import.

Public API re-exported here:

- :func:`stunscope.parser.parse_stun_message` — parse raw bytes into a
  structured :class:`~stunscope.models.StunMessage`.
- :func:`stunscope.parser.looks_like_stun` — cheap structural check used by
  the capture layer.
- :class:`stunscope.filters.PacketFilter` — predicate used by CLI and GUI.
- :func:`stunscope.exporter.export_csv` — shared CSV writer.

See ``docs/architecture.md`` for the module layout.
"""

from __future__ import annotations

from stunscope.filters import PacketFilter
from stunscope.models import (
    PacketRecord,
    StunAttribute,
    StunMessage,
)
from stunscope.parser import (
    MAGIC_COOKIE,
    MAGIC_COOKIE_BYTES,
    MESSAGE_CLASSES,
    MESSAGE_METHODS,
    HEADER_LENGTH,
    looks_like_stun,
    parse_stun_message,
)

__version__ = "1.0.0"
__all__ = [
    "__version__",
    "MAGIC_COOKIE",
    "MAGIC_COOKIE_BYTES",
    "HEADER_LENGTH",
    "MESSAGE_CLASSES",
    "MESSAGE_METHODS",
    "PacketFilter",
    "PacketRecord",
    "StunAttribute",
    "StunMessage",
    "looks_like_stun",
    "parse_stun_message",
]
