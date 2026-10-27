"""Packet filtering shared by the CLI, the GUI, and the CSV exporter.

A :class:`PacketFilter` is a plain value object evaluated against
:class:`~stunscope.models.PacketRecord` instances. The GUI keeps a live
instance bound to its Filters page; the CLI applies one instance before
display/export. Both use the exact same code path.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from stunscope.models import (
    PARSE_MALFORMED,
    PARSE_OK,
    PacketRecord,
)
from stunscope.parser import (
    BINDING_ERROR,
    BINDING_INDICATION,
    BINDING_REQUEST,
    BINDING_SUCCESS,
    decode_message_type,
)

# Normalized filter tokens for concrete STUN message types. Users can pass
# any of these (case-insensitive) to the CLI ``--message-type`` flag or
# select them in the GUI Filters page. Class-only tokens ("request",
# "success", "error", "indication") and raw hex such as ``0x0111`` are also
# accepted; see :func:`_parse_message_type_token`.
MESSAGE_TYPE_TOKENS = {
    "binding-request": (BINDING_REQUEST,),
    "binding-indication": (BINDING_INDICATION,),
    "binding-success": (BINDING_SUCCESS,),
    "binding-success-response": (BINDING_SUCCESS,),
    "binding-error": (BINDING_ERROR,),
    "binding-error-response": (BINDING_ERROR,),
    "binding": (BINDING_REQUEST, BINDING_INDICATION, BINDING_SUCCESS, BINDING_ERROR),
}

_CLASS_TOKENS = {
    "request": 0,
    "indication": 1,
    "success": 2,
    "error": 3,
}


class FilterError(ValueError):
    """Raised when a filter expression cannot be understood."""


def _parse_message_type_token(token: str) -> tuple[str, object]:
    """Return ``("types", tuple_of_ints)`` or ``("class", class_code)``."""
    key = token.strip().lower()
    if key in _CLASS_TOKENS:
        return ("class", _CLASS_TOKENS[key])
    if key in MESSAGE_TYPE_TOKENS:
        return ("types", MESSAGE_TYPE_TOKENS[key])
    if key.startswith("0x"):
        try:
            value = int(key, 16)
        except ValueError:
            raise FilterError(f"invalid message type: {token!r}") from None
        if not 0 <= value <= 0xFFFF:
            raise FilterError(f"message type out of range: {token!r}")
        return ("types", (value,))
    if key.isdigit():
        value = int(key)
        if not 0 <= value <= 0xFFFF:
            raise FilterError(f"message type out of range: {token!r}")
        return ("types", (value,))
    raise FilterError(
        f"unknown message type {token!r}; expected one of "
        + ", ".join(sorted(_CLASS_TOKENS))
        + ", binding, binding-request, binding-indication, binding-success, "
        "binding-error, or a hex value like 0x0111"
    )


def _ip_matches(pattern: str, candidate: str) -> bool:
    """Match an IP address exactly, by CIDR prefix, or with a ``*`` suffix."""
    pattern = pattern.strip()
    if not pattern or not candidate:
        return False
    if "*" in pattern:
        prefix = pattern.split("*", 1)[0]
        return candidate.startswith(prefix)
    if "/" in pattern:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return address in network
    return pattern == candidate


def _normalize_transaction_id(value: str) -> str:
    cleaned = value.strip().lower().replace("-", "").replace(" ", "")
    return "".join(ch for ch in cleaned if ch in "0123456789abcdef")


@dataclass
class PacketFilter:
    """Composite predicate over captured records.

    Attributes left at their default (empty / "any") do not restrict
    anything.
    """

    message_type: str = ""  # token from MESSAGE_TYPE_TOKENS or hex
    src_ip: str = ""
    dst_ip: str = ""
    transaction_id: str = ""  # hex; dashes, spaces, and case are ignored
    validity: str = "any"  # "any" | "valid" | "malformed"
    search: str = ""  # case-insensitive free-text match

    def __post_init__(self) -> None:
        # Fail fast on bad tokens at construction time so both interfaces
        # can surface a clear error before capture starts.
        if self.message_type:
            _parse_message_type_token(self.message_type)
        if self.validity not in ("any", "valid", "malformed"):
            raise FilterError(
                f"validity must be 'any', 'valid' or 'malformed', got {self.validity!r}"
            )

    # -- evaluation --------------------------------------------------------
    def is_active(self) -> bool:
        """True when at least one criterion would filter something out."""
        return bool(
            self.message_type
            or self.src_ip
            or self.dst_ip
            or self.transaction_id
            or self.validity != "any"
            or self.search
        )

    def matches(self, record: PacketRecord) -> bool:
        return (
            self._matches_type(record)
            and self._matches_ip(record)
            and self._matches_transaction(record)
            and self._matches_validity(record)
            and self._matches_search(record)
        )

    def _matches_type(self, record: PacketRecord) -> bool:
        if not self.message_type:
            return True
        message = record.message
        if message is None or not message.valid:
            return False
        kind, value = _parse_message_type_token(self.message_type)
        if kind == "types":
            return message.message_type in value
        # kind == "class"
        _, class_code = decode_message_type(message.message_type)
        return class_code == value

    def _matches_ip(self, record: PacketRecord) -> bool:
        if self.src_ip and not _ip_matches(self.src_ip, record.src_ip):
            return False
        if self.dst_ip and not _ip_matches(self.dst_ip, record.dst_ip):
            return False
        return True

    def _matches_transaction(self, record: PacketRecord) -> bool:
        if not self.transaction_id:
            return True
        wanted = _normalize_transaction_id(self.transaction_id)
        actual = _normalize_transaction_id(record.transaction_id())
        if not wanted or not actual:
            return False
        return actual == wanted or actual.startswith(wanted)

    def _matches_validity(self, record: PacketRecord) -> bool:
        if self.validity == "any":
            return True
        if self.validity == "valid":
            return record.parse_status == PARSE_OK
        return record.parse_status == PARSE_MALFORMED

    def _matches_search(self, record: PacketRecord) -> bool:
        if not self.search:
            return True
        needle = self.search.lower()
        return needle in self.search_text(record).lower()

    @staticmethod
    def search_text(record: PacketRecord) -> str:
        """All user-meaningful text of a record, for free-text search."""
        parts = [
            record.src_ip,
            str(record.src_port),
            record.dst_ip,
            str(record.dst_port),
            record.interface,
            record.protocol,
            record.type_label(),
            record.transaction_id(),
            record.note,
        ]
        message = record.message
        if message is not None:
            parts.append(message.error)
            parts.extend(message.warnings)
            parts.extend(attr.summary() for attr in message.attributes)
        return " ".join(p for p in parts if p)

    # -- display -----------------------------------------------------------
    def describe(self) -> str:
        active = []
        if self.message_type:
            active.append(f"message type = {self.message_type}")
        if self.src_ip:
            active.append(f"source IP = {self.src_ip}")
        if self.dst_ip:
            active.append(f"destination IP = {self.dst_ip}")
        if self.transaction_id:
            active.append(f"transaction ID = {self.transaction_id}")
        if self.validity != "any":
            active.append(f"validity = {self.validity}")
        if self.search:
            active.append(f"search = {self.search!r}")
        if not active:
            return "no active filters"
        return "; ".join(active)
