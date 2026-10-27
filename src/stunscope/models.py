"""Structured data objects shared by the parser, CLI, GUI, and CSV exporter.

Every layer of STUNScope communicates through the dataclasses defined here,
so a packet is parsed exactly once and rendered by whichever interface the
user chose. All objects are plain ``dataclasses`` (no GUI imports) so they
can be used from headless CLI runs and from unit tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Status values used across the app.
PARSE_OK = "valid"
PARSE_MALFORMED = "malformed"

ATTRIBUTE_OK = "ok"
ATTRIBUTE_UNSUPPORTED = "unsupported"
ATTRIBUTE_MALFORMED = "malformed"

# Not-applicable marker. The CSV exporter uses this to distinguish "field
# does not exist for this row" from an empty string value.
NOT_AVAILABLE = "n/a"


@dataclass
class DecodedAddress:
    """A decoded MAPPED-ADDRESS / XOR-MAPPED-ADDRESS value."""

    family: str  # "IPv4" or "IPv6"
    address: str  # canonical textual form
    port: int

    def as_dict(self) -> dict:
        return {"family": self.family, "address": self.address, "port": self.port}


@dataclass
class StunAttribute:
    """A single STUN attribute.

    ``decoded`` holds a JSON-friendly dict for known attribute types
    (e.g. ``{"family": "IPv4", "address": "203.0.113.7", "port": 32853}`` for
    XOR-MAPPED-ADDRESS, ``{"code": 401, "reason": "Unauthorized"}`` for
    ERROR-CODE, ``{"value": "text"}`` for textual attributes). It is ``None``
    for unknown attribute types, which keeps the raw bytes in ``raw``.
    """

    type: int
    type_name: str
    length: int  # declared value length, excluding padding
    raw: bytes  # value bytes, excluding padding
    decoded: Optional[dict] = None
    status: str = ATTRIBUTE_OK
    note: str = ""

    def summary(self) -> str:
        """One-line human summary used by the CLI and the GUI inspector."""
        if self.decoded is None:
            return self.type_name
        if "address" in self.decoded:
            return f"{self.type_name}: {self.decoded['address']}:{self.decoded['port']}"
        if "code" in self.decoded:
            return f"{self.type_name}: {self.decoded['code']} {self.decoded.get('reason', '')}".strip()
        if "value_hex" in self.decoded:
            return f"{self.type_name}: {self.decoded['value_hex']}"
        value = self.decoded.get("value")
        if isinstance(value, str):
            return f"{self.type_name}: {value}"
        return self.type_name


@dataclass
class StunMessage:
    """A parsed STUN message, or a well-explained failure to parse one.

    ``valid`` is False when the message violates the RFC 8489 framing rules
    (truncated header, wrong magic cookie, length not a multiple of four,
    attribute overruns the message body, ...). In that case ``error``
    contains a readable diagnostic and never an exception.

    ``warnings`` collects non-fatal observations (trailing bytes after the
    message body, unknown comprehension-optional attributes, an unverified
    MESSAGE-INTEGRITY, ...).

    Address-attribution note: an XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS) in a
    Binding response is the address the *server* observed for the *sender*
    of the request — typically the local network's NAT binding. It is not,
    by itself, the address of any remote call participant.
    """

    valid: bool
    error: str = ""
    warnings: list[str] = field(default_factory=list)

    message_type: int = 0
    message_type_hex: str = "0x0000"
    message_length: int = 0
    method: int = 0
    method_name: str = "Unknown"
    message_class: str = "Unknown"
    transaction_id: str = ""  # 24-char lowercase hex
    transaction_id_bytes: bytes = b""

    attributes: list[StunAttribute] = field(default_factory=list)
    raw: bytes = b""

    # Convenience lookups -------------------------------------------------
    def attribute(self, attr_type: int) -> Optional[StunAttribute]:
        for attr in self.attributes:
            if attr.type == attr_type:
                return attr
        return None

    def attributes_of_type(self, attr_type: int) -> list[StunAttribute]:
        return [a for a in self.attributes if a.type == attr_type]

    def mapped_address(self) -> Optional[DecodedAddress]:
        """Prefer XOR-MAPPED-ADDRESS, fall back to MAPPED-ADDRESS."""
        from stunscope.parser import (
            ATTR_MAPPED_ADDRESS,
            ATTR_XOR_MAPPED_ADDRESS,
        )

        for attr_type in (ATTR_XOR_MAPPED_ADDRESS, ATTR_MAPPED_ADDRESS):
            attr = self.attribute(attr_type)
            if attr is not None and attr.decoded and "address" in attr.decoded:
                return DecodedAddress(
                    family=attr.decoded["family"],
                    address=attr.decoded["address"],
                    port=attr.decoded["port"],
                )
        return None

    def error_code(self) -> Optional[int]:
        attr = self.attribute(0x0009)
        if attr is not None and attr.decoded and "code" in attr.decoded:
            return int(attr.decoded["code"])
        return None

    def is_binding_request(self) -> bool:
        return self.valid and self.message_type == 0x0001

    def is_binding_success(self) -> bool:
        return self.valid and self.message_type == 0x0101

    def is_binding_error(self) -> bool:
        return self.valid and self.message_type == 0x0111

    def type_label(self) -> str:
        """Human label, e.g. 'Binding Request' or 'Malformed (0x0101)'."""
        if not self.valid:
            return f"Malformed ({self.message_type_hex})"
        return f"{self.method_name} {self.message_class}"


@dataclass
class PacketRecord:
    """A captured datagram plus its parsed STUN message.

    ``payload`` keeps a bounded copy of the raw STUN bytes for the packet
    inspector. ``parse_status`` is ``valid``/``malformed``.
    """

    timestamp: float  # epoch seconds
    interface: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "UDP"
    message: Optional[StunMessage] = None
    parse_status: str = PARSE_OK
    note: str = ""
    payload: bytes = b""

    def type_label(self) -> str:
        return self.message.type_label() if self.message else "Not STUN"

    def transaction_id(self) -> str:
        return self.message.transaction_id if self.message else ""
