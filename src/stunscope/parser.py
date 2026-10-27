"""Shared STUN (RFC 8489) protocol parser.

This module is the single protocol authority used by both the CLI and the
GUI. It converts raw UDP payload bytes into the structured dataclasses from
:mod:`stunscope.models` and never raises on malformed input — every
protocol violation is reported as a readable diagnostic on the returned
:class:`~stunscope.models.StunMessage`.

Scope and limits (documented, deliberate):

- Only UDP-carried STUN is analyzed. STUN-over-TCP uses a 4-byte length
  framing prefix; TCP framing may be added later but the capture layer
  currently restricts itself to UDP.
- Only RFC 5389/8489 messages with the magic cookie ``0x2112A442`` are
  recognized. Legacy RFC 3489 messages (no cookie) are reported as
  malformed/unsupported rather than mis-decoded.

Address-attribution warning: an XOR-MAPPED-ADDRESS or MAPPED-ADDRESS inside
a Binding Success Response is the address the *STUN server* observed for
the *request sender* — typically the NAT binding of the local network. It is
NOT automatically the address of a remote call participant.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from stunscope.models import (
    ATTRIBUTE_MALFORMED,
    ATTRIBUTE_OK,
    ATTRIBUTE_UNSUPPORTED,
    StunAttribute,
    StunMessage,
)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

HEADER_LENGTH = 20
MAGIC_COOKIE = 0x2112A442
MAGIC_COOKIE_BYTES = MAGIC_COOKIE.to_bytes(4, "big")  # b"\x21\x12\xa4\x42"

MESSAGE_CLASSES = {
    0: "Request",
    1: "Indication",
    2: "Success Response",
    3: "Error Response",
}

# IANA-registered STUN methods (Binding) plus TURN methods, for nicer labels.
MESSAGE_METHODS = {
    0x001: "Binding",
    0x002: "SharedSecret (historic)",
    0x003: "Allocate",
    0x004: "Refresh",
    0x006: "Send",
    0x007: "Data",
    0x008: "CreatePermission",
    0x009: "ChannelBind",
    0x00A: "Connect",
    0x00B: "ConnectionBind",
}

# Well-known message types.
BINDING_REQUEST = 0x0001
BINDING_INDICATION = 0x0011
BINDING_SUCCESS = 0x0101
BINDING_ERROR = 0x0111

# Attribute type registry.
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_RESPONSE_ADDRESS = 0x0004  # historic (RFC 3489)
ATTR_CHANGE_ADDRESS = 0x0005  # historic (RFC 3489)
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_UNKNOWN_ATTRIBUTES = 0x000A
ATTR_CHANNEL_NUMBER = 0x000C
ATTR_LIFETIME = 0x000D
ATTR_XOR_PEER_ADDRESS = 0x0012
ATTR_DATA = 0x0013
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_XOR_RELAYED_ADDRESS = 0x0016
ATTR_REQUESTED_TRANSPORT = 0x0019
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_PRIORITY = 0x0024
ATTR_USE_CANDIDATE = 0x0025
ATTR_SOFTWARE = 0x8022
ATTR_ALTERNATE_SERVER = 0x8023
ATTR_FINGERPRINT = 0x8028
ATTR_ICE_CONTROLLED = 0x8029
ATTR_ICE_CONTROLLING = 0x802A

ATTRIBUTE_NAMES = {
    ATTR_MAPPED_ADDRESS: "MAPPED-ADDRESS",
    ATTR_RESPONSE_ADDRESS: "RESPONSE-ADDRESS (historic)",
    ATTR_CHANGE_ADDRESS: "CHANGE-ADDRESS (historic)",
    ATTR_USERNAME: "USERNAME",
    ATTR_MESSAGE_INTEGRITY: "MESSAGE-INTEGRITY",
    ATTR_ERROR_CODE: "ERROR-CODE",
    ATTR_UNKNOWN_ATTRIBUTES: "UNKNOWN-ATTRIBUTES",
    ATTR_CHANNEL_NUMBER: "CHANNEL-NUMBER",
    ATTR_LIFETIME: "LIFETIME",
    ATTR_XOR_PEER_ADDRESS: "XOR-PEER-ADDRESS",
    ATTR_DATA: "DATA",
    ATTR_REALM: "REALM",
    ATTR_NONCE: "NONCE",
    ATTR_XOR_RELAYED_ADDRESS: "XOR-RELAYED-ADDRESS",
    ATTR_REQUESTED_TRANSPORT: "REQUESTED-TRANSPORT",
    ATTR_XOR_MAPPED_ADDRESS: "XOR-MAPPED-ADDRESS",
    ATTR_PRIORITY: "PRIORITY",
    ATTR_USE_CANDIDATE: "USE-CANDIDATE",
    ATTR_SOFTWARE: "SOFTWARE",
    ATTR_ALTERNATE_SERVER: "ALTERNATE-SERVER",
    ATTR_FINGERPRINT: "FINGERPRINT",
    ATTR_ICE_CONTROLLED: "ICE-CONTROLLED",
    ATTR_ICE_CONTROLLING: "ICE-CONTROLLING",
}

# Attribute types the CLI/GUI/CSV export specially render.
TEXT_ATTRIBUTES = {
    ATTR_USERNAME,
    ATTR_REALM,
    ATTR_NONCE,
    ATTR_SOFTWARE,
}

# Attribute types whose value decodes to an address (family/port/bytes).
ADDRESS_ATTRIBUTES = {
    ATTR_MAPPED_ADDRESS,
    ATTR_XOR_MAPPED_ADDRESS,
    ATTR_XOR_PEER_ADDRESS,
    ATTR_XOR_RELAYED_ADDRESS,
}

# Attributes that are XOR-encoded with the magic cookie (+ transaction ID).
XOR_ADDRESS_ATTRIBUTES = {
    ATTR_XOR_MAPPED_ADDRESS,
    ATTR_XOR_PEER_ADDRESS,
    ATTR_XOR_RELAYED_ADDRESS,
}


class _AttributeError(Exception):
    """Internal: a malformed attribute value. Never escapes this module."""


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------


def decode_message_type(message_type: int) -> tuple[int, int]:
    """Split the 16-bit message type into ``(method, class_code)``.

    STUN interleaves two class bits into the method bit layout
    (RFC 8489 section 5): C1 sits at bit 8, C0 at bit 4, and the 12 method
    bits occupy bits 0-3, 5-7, and 9-13.
    """
    class_code = ((message_type & 0x0100) >> 7) | ((message_type & 0x0010) >> 4)
    method = (
        (message_type & 0x000F)
        | ((message_type & 0x00E0) >> 1)
        | ((message_type & 0x3E00) >> 2)
    )
    return method, class_code


def method_name(method: int) -> str:
    return MESSAGE_METHODS.get(method, f"Method-0x{method:03X}")


def class_name(class_code: int) -> str:
    return MESSAGE_CLASSES.get(class_code, "Unknown")


def message_type_label(message_type: int) -> str:
    method, cls = decode_message_type(message_type)
    return f"{method_name(method)} {class_name(cls)}"


def attribute_name(attr_type: int) -> str:
    return ATTRIBUTE_NAMES.get(attr_type, f"Unknown (0x{attr_type:04X})")


def is_comprehension_optional(attr_type: int) -> bool:
    """Attributes 0x0000-0x7FFF must be understood ("comprehension-required")."""
    return attr_type >= 0x8000


# ---------------------------------------------------------------------------
# Public structural check (used by the capture layer)
# ---------------------------------------------------------------------------


def looks_like_stun(payload: bytes) -> bool:
    """Return True if ``payload`` is plausibly a complete STUN message.

    This is a *structural* check that never looks at ports alone:

    - at least a 20-byte header,
    - the two leading zero bits required by RFC 8489,
    - the magic cookie at bytes 4-7,
    - a declared message length that is a multiple of four and fully
      present in the datagram.
    """
    if payload is None or len(payload) < HEADER_LENGTH:
        return False
    if payload[0] & 0xC0 != 0:
        return False
    if payload[4:8] != MAGIC_COOKIE_BYTES:
        return False
    message_length = int.from_bytes(payload[2:4], "big")
    if message_length % 4 != 0:
        return False
    if len(payload) < HEADER_LENGTH + message_length:
        return False
    return True


def maybe_stun(payload: bytes) -> bool:
    """Return True if ``payload`` is *plausibly* a STUN message.

    The capture layer uses this loose structural check so that malformed
    STUN messages (bad lengths, truncated bodies) still reach the parser
    and surface as readable diagnostics instead of being silently
    dropped. :func:`looks_like_stun` is the strict "definitely complete
    and well-framed" variant.
    """
    if payload is None or len(payload) < 8:
        return False
    if payload[0] & 0xC0 != 0:
        return False
    return payload[4:8] == MAGIC_COOKIE_BYTES


# ---------------------------------------------------------------------------
# Attribute value decoders
# ---------------------------------------------------------------------------


def _decode_text(value: bytes, type_name: str) -> dict:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        text = value.decode("utf-8", errors="replace")
        return {"value": text, "note": f"{type_name} contained invalid UTF-8"}
    return {"value": text}


def _decode_address_value(value: bytes, xor_key: Optional[bytes]) -> dict:
    """Decode a MAPPED-ADDRESS-style value.

    Layout (RFC 8489 sections 14.1/14.2): one zero byte, a family byte
    (0x01 IPv4, 0x02 IPv6), a 16-bit port, then 4 or 16 address bytes.

    When ``xor_key`` is given it must be at least 16 bytes: the magic
    cookie (4 bytes) followed by the 12-byte transaction ID. Ports are
    XORed with the top 16 bits of the cookie (``0x2112``); IPv4
    addresses with the cookie; IPv6 addresses with the full 128-bit
    mask.
    """
    if len(value) < 4:
        raise _AttributeError("value shorter than the 4-byte minimum")
    family = value[1]
    port = int.from_bytes(value[2:4], "big")
    if xor_key is not None and len(xor_key) < 16:
        # Should be impossible from the caller; guard against misuse.
        raise _AttributeError("internal: XOR key too short")
    if family == 0x01:
        if len(value) != 8:
            raise _AttributeError(f"IPv4 address value must be 8 bytes, got {len(value)}")
        address_bytes = value[4:8]
        if xor_key is not None:
            port ^= (MAGIC_COOKIE >> 16) & 0xFFFF
            address_bytes = bytes(a ^ b for a, b in zip(address_bytes, xor_key[:4]))
        address = str(ipaddress.IPv4Address(int.from_bytes(address_bytes, "big")))
        return {"family": "IPv4", "address": address, "port": port}
    if family == 0x02:
        if len(value) != 20:
            raise _AttributeError(f"IPv6 address value must be 20 bytes, got {len(value)}")
        address_bytes = value[4:20]
        if xor_key is not None:
            port ^= (MAGIC_COOKIE >> 16) & 0xFFFF
            address_bytes = bytes(a ^ b for a, b in zip(address_bytes, xor_key[:16]))
        address = str(ipaddress.IPv6Address(int.from_bytes(address_bytes, "big")))
        return {"family": "IPv6", "address": address, "port": port}
    raise _AttributeError(f"unknown address family 0x{family:02X}")


def _decode_error_code(value: bytes) -> dict:
    """ERROR-CODE: 21 reserved bits, 3 class bits, 8-bit number, reason."""
    if len(value) < 4:
        raise _AttributeError(f"ERROR-CODE needs 4 header bytes, got {len(value)}")
    class_digit = value[2] & 0x07
    number = value[3]
    code = class_digit * 100 + number
    reason = value[4:].decode("utf-8", errors="replace")
    decoded: dict = {"code": code, "reason": reason}
    if not 300 <= code <= 699:
        decoded["note"] = f"error code {code} outside the 300-699 range"
    return decoded


def _decode_channel_number(value: bytes) -> dict:
    if len(value) != 4:
        raise _AttributeError(f"CHANNEL-NUMBER must be 4 bytes, got {len(value)}")
    channel = int.from_bytes(value[0:2], "big")
    if not 0x4000 <= channel <= 0x7FFF:
        return {"value": f"0x{channel:04X}", "note": f"channel 0x{channel:04X} outside 0x4000-0x7FFF"}
    return {"value": f"0x{channel:04X}"}


def _decode_lifetime(value: bytes) -> dict:
    if len(value) != 4:
        raise _AttributeError(f"LIFETIME must be 4 bytes, got {len(value)}")
    return {"value": f"{int.from_bytes(value, 'big')} s"}


def _decode_requested_transport(value: bytes) -> dict:
    if len(value) != 4:
        raise _AttributeError(f"REQUESTED-TRANSPORT must be 4 bytes, got {len(value)}")
    proto = value[0]
    names = {6: "TCP", 17: "UDP", 132: "SCTP"}
    label = names.get(proto, f"protocol {proto}")
    return {"value": label}


def _decode_uint32(value: bytes, type_name: str) -> dict:
    if len(value) != 4:
        raise _AttributeError(f"{type_name} must be 4 bytes, got {len(value)}")
    return {"value": int.from_bytes(value, "big")}


def _decode_uint64(value: bytes, type_name: str) -> dict:
    if len(value) != 8:
        raise _AttributeError(f"{type_name} must be 8 bytes, got {len(value)}")
    return {"value_hex": value.hex()}


def _decode_unknown_attributes(value: bytes) -> dict:
    if len(value) % 2 != 0:
        raise _AttributeError(f"UNKNOWN-ATTRIBUTES length {len(value)} is not even")
    types = [int.from_bytes(value[i:i + 2], "big") for i in range(0, len(value), 2)]
    return {"value": ", ".join(attribute_name(t) for t in types)}


def decode_attribute_value(attr_type: int, value: bytes, transaction_id: bytes) -> tuple[Optional[dict], str, str]:
    """Decode an attribute value.

    Returns ``(decoded, status, note)`` where ``decoded`` is None for
    unknown attribute types and ``status``/``note`` explain how the value
    was treated.
    """
    name = attribute_name(attr_type)
    if attr_type in ADDRESS_ATTRIBUTES:
        xor_key = (MAGIC_COOKIE_BYTES + transaction_id) if attr_type in XOR_ADDRESS_ATTRIBUTES else None
        decoded = _decode_address_value(value, xor_key)
        note = ""
        if attr_type == ATTR_XOR_MAPPED_ADDRESS:
            note = (
                "Server-observed mapping of the request sender; not a "
                "remote participant address by itself."
            )
        elif attr_type == ATTR_XOR_RELAYED_ADDRESS:
            note = "TURN relay allocation address."
        return decoded, ATTRIBUTE_OK, note
    if attr_type in TEXT_ATTRIBUTES:
        decoded = _decode_text(value, name)
        note = decoded.pop("note", "")
        return decoded, ATTRIBUTE_OK, note
    if attr_type == ATTR_ERROR_CODE:
        decoded = _decode_error_code(value)
        return decoded, ATTRIBUTE_OK, decoded.pop("note", "")
    if attr_type == ATTR_MESSAGE_INTEGRITY:
        if len(value) != 20:
            raise _AttributeError(f"MESSAGE-INTEGRITY must be 20 bytes, got {len(value)}")
        return (
            {"value_hex": value.hex()},
            ATTRIBUTE_OK,
            "HMAC-SHA1 present; not verified (no credentials).",
        )
    if attr_type == ATTR_FINGERPRINT:
        if len(value) != 4:
            raise _AttributeError(f"FINGERPRINT must be 4 bytes, got {len(value)}")
        return (
            {"value": f"0x{int.from_bytes(value, 'big'):08X}"},
            ATTRIBUTE_OK,
            "CRC32 present; not verified.",
        )
    if attr_type == ATTR_CHANNEL_NUMBER:
        decoded = _decode_channel_number(value)
        return decoded, ATTRIBUTE_OK, decoded.pop("note", "")
    if attr_type == ATTR_LIFETIME:
        return _decode_lifetime(value), ATTRIBUTE_OK, ""
    if attr_type == ATTR_REQUESTED_TRANSPORT:
        return _decode_requested_transport(value), ATTRIBUTE_OK, ""
    if attr_type == ATTR_PRIORITY:
        return _decode_uint32(value, name), ATTRIBUTE_OK, ""
    if attr_type in (ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING):
        return _decode_uint64(value, name), ATTRIBUTE_OK, "tie-breaker value."
    if attr_type == ATTR_UNKNOWN_ATTRIBUTES:
        return _decode_unknown_attributes(value), ATTRIBUTE_OK, ""
    if attr_type == ATTR_DATA:
        return {"value_hex": value.hex()[:64] + ("…" if len(value) > 32 else "")}, ATTRIBUTE_OK, "opaque application data."
    if attr_type == ATTR_USE_CANDIDATE:
        if len(value) != 0:
            raise _AttributeError(f"USE-CANDIDATE must be empty, got {len(value)} bytes")
        return {"value": ""}, ATTRIBUTE_OK, ""
    # Everything else is stored raw and clearly labeled.
    if is_comprehension_optional(attr_type):
        return None, ATTRIBUTE_UNSUPPORTED, "Unknown comprehension-optional attribute; raw bytes kept."
    return None, ATTRIBUTE_UNSUPPORTED, "Unknown comprehension-required attribute; raw bytes kept."


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def parse_stun_message(data: bytes) -> StunMessage:
    """Parse raw STUN message bytes into a :class:`StunMessage`.

    This function never raises for malformed input. Header-level
    violations produce ``valid=False`` with a readable ``error`` and no
    attributes. Attribute-level violations are attached to the offending
    attribute and also flag the message, while everything that parsed
    cleanly before the failure is retained.
    """
    message = StunMessage(valid=False, raw=bytes(data or b""))
    warnings: list[str] = message.warnings

    if not data:
        message.error = "empty payload"
        return message
    if len(data) < HEADER_LENGTH:
        message.error = f"truncated header: {len(data)} of {HEADER_LENGTH} bytes present"
        if len(data) >= 2:
            message.message_type = int.from_bytes(data[0:2], "big")
            message.message_type_hex = f"0x{message.message_type:04X}"
        return message

    # Header fields ---------------------------------------------------------
    message.message_type = int.from_bytes(data[0:2], "big")
    message.message_type_hex = f"0x{message.message_type:04X}"
    message.message_length = int.from_bytes(data[2:4], "big")
    method, class_code = decode_message_type(message.message_type)
    message.method = method
    message.method_name = method_name(method)
    message.message_class = class_name(class_code)

    if message.message_type & 0xC000:
        message.error = (
            f"invalid message type {message.message_type_hex}: "
            "two leading bits must be zero"
        )
        return message
    if data[4:8] != MAGIC_COOKIE_BYTES:
        message.error = "missing STUN magic cookie (possibly a legacy RFC 3489 message)"
        return message

    message.transaction_id_bytes = data[8:20]
    message.transaction_id = message.transaction_id_bytes.hex()

    body_end = HEADER_LENGTH + message.message_length
    if message.message_length % 4 != 0:
        message.error = (
            f"message length {message.message_length} is not a multiple of 4"
        )
        return message
    if len(data) < body_end:
        message.error = (
            f"truncated message: header declares {message.message_length} "
            f"body bytes but only {len(data) - HEADER_LENGTH} are present"
        )
        return message
    if len(data) > body_end:
        trailing = len(data) - body_end
        warnings.append(
            f"{trailing} trailing bytes after the STUN message body were ignored"
        )

    # Attribute loop --------------------------------------------------------
    attributes: list[StunAttribute] = []
    offset = HEADER_LENGTH
    failed = ""
    while offset < body_end:
        if offset + 4 > body_end:
            failed = f"attribute header at byte {offset} overruns the message body"
            break
        attr_type = int.from_bytes(data[offset:offset + 2], "big")
        attr_len = int.from_bytes(data[offset + 2:offset + 4], "big")
        value_start = offset + 4
        value_end = value_start + attr_len
        if value_end > body_end:
            failed = (
                f"attribute {attribute_name(attr_type)} at byte {offset} "
                f"declares {attr_len} bytes but overruns the message body "
                f"({body_end - value_start} bytes available)"
            )
            break

        raw_value = data[value_start:value_end]
        status = ATTRIBUTE_OK
        note = ""
        decoded: Optional[dict] = None
        try:
            decoded, status, note = decode_attribute_value(
                attr_type, raw_value, message.transaction_id_bytes
            )
        except _AttributeError as exc:
            status = ATTRIBUTE_MALFORMED
            note = str(exc)
            failed = (
                f"malformed {attribute_name(attr_type)} attribute at byte {offset}: {exc}"
            )

        attributes.append(
            StunAttribute(
                type=attr_type,
                type_name=attribute_name(attr_type),
                length=attr_len,
                raw=raw_value,
                decoded=decoded,
                status=status,
                note=note,
            )
        )

        if status == ATTRIBUTE_UNSUPPORTED and not is_comprehension_optional(attr_type):
            warnings.append(
                f"unknown comprehension-required attribute {attribute_name(attr_type)} "
                f"(0x{attr_type:04X}); a conforming STUN agent would reject this message"
            )

        if failed:
            break

        padding = (-attr_len) % 4
        next_offset = value_end + padding
        if next_offset > body_end:
            # Impossible once the header length check passes; kept as a
            # defensive guard with a clear diagnostic.
            failed = f"attribute padding at byte {value_end} overruns the message body"
            break
        offset = next_offset

    message.attributes = attributes

    if failed:
        message.error = failed
        return message

    message.valid = True
    return message


# ---------------------------------------------------------------------------
# Rendering helpers shared by CLI and GUI
# ---------------------------------------------------------------------------


def short_transaction_id(transaction_id: str, keep: int = 8) -> str:
    if len(transaction_id) <= keep * 2:
        return transaction_id
    return f"{transaction_id[:keep]}…{transaction_id[-4:]}"


def format_hex_dump(data: bytes, limit: int = 512) -> str:
    """Classic offset/hex/ASCII dump used by the packet inspector."""
    shown = data[:limit]
    suffix = f"\n… ({len(data) - limit} more bytes)" if len(data) > limit else ""
    lines = []
    for base in range(0, len(shown), 16):
        chunk = shown[base:base + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "·" for b in chunk)
        lines.append(f"{base:04x}  {hex_part:<47}  |{ascii_part}|")
    return "\n".join(lines) + suffix


def describe_stun_message(message: StunMessage, indent: str = "  ") -> list[str]:
    """Plain-text, line-oriented description for CLI verbose output."""
    lines = [
        f"Message type:      {message.message_type_hex}"
        f" ({message.method_name} {message.message_class})",
        f"Message length:    {message.message_length} bytes (body)",
        f"Transaction ID:   {message.transaction_id}",
        "Magic cookie:      0x2112A442",
        f"Valid:             {'yes' if message.valid else 'no'}",
    ]
    if message.error:
        lines.append(f"Error:             {message.error}")
    for warning in message.warnings:
        lines.append(f"Warning:           {warning}")
    if message.attributes:
        lines.append(f"Attributes ({len(message.attributes)}):")
        for attr in message.attributes:
            line = f"{indent}{attr.type_name} (0x{attr.type:04X}, {attr.length} bytes)"
            if attr.decoded is not None:
                if "address" in attr.decoded:
                    line += (
                        f" = {attr.decoded['family']} "
                        f"{attr.decoded['address']}:{attr.decoded['port']}"
                    )
                elif "code" in attr.decoded:
                    line += f" = {attr.decoded['code']} {attr.decoded.get('reason', '')}".rstrip()
                elif "value" in attr.decoded and isinstance(attr.decoded["value"], (str, int)):
                    line += f" = {attr.decoded['value']}"
                elif "value_hex" in attr.decoded:
                    line += f" = {attr.decoded['value_hex']}"
            if attr.status != ATTRIBUTE_OK:
                line += f" [{attr.status}]"
            if attr.note:
                line += f" — {attr.note}"
            lines.append(indent + line)
    else:
        lines.append("Attributes:        none")
    return lines
