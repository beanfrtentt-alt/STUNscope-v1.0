"""Deterministic synthetic STUN messages for tests and examples.

Every fixture in this module is synthetic. All addresses come from the
RFC 5737 / RFC 3849 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32) — never from real networks or captured
private traffic.
"""

from __future__ import annotations

import struct

from stunscope.parser import (
    ATTR_ERROR_CODE,
    ATTR_FINGERPRINT,
    ATTR_MAPPED_ADDRESS,
    ATTR_MESSAGE_INTEGRITY,
    ATTR_NONCE,
    ATTR_REALM,
    ATTR_SOFTWARE,
    ATTR_USERNAME,
    ATTR_XOR_MAPPED_ADDRESS,
    MAGIC_COOKIE_BYTES,
)

# A fixed transaction ID used across tests (12 bytes).
TEST_TRANSACTION_ID = bytes.fromhex("00112233445566778899aabb")
TEST_TRANSACTION_HEX = TEST_TRANSACTION_ID.hex()

ALT_TRANSACTION_ID = bytes.fromhex("b7e2f4a6c8d0e2f4a6b8c0d2")
ALT_TRANSACTION_HEX = ALT_TRANSACTION_ID.hex()

DOC_IPV4 = "192.0.2.34"  # RFC 5737 documentation address
DOC_IPV4_PORT = 0x1234  # 4660

DOC_IPV6 = "2001:db8:1234:5678:11:2233:4455:6666"  # RFC 3849 documentation range
DOC_IPV6_PORT = 0x5678  # 22136


def ip_bytes(address: str) -> bytes:
    import ipaddress

    return ipaddress.ip_address(address).packed


def xor_address_value(address: str, port: int, transaction_id: bytes) -> bytes:
    """Build an XOR-MAPPED-ADDRESS attribute value per RFC 8489 §14.2."""
    packed = ip_bytes(address)
    port_bytes = struct.pack(">H", port ^ 0x2112)
    if len(packed) == 4:
        family = b"\x00\x01"
        mask = MAGIC_COOKIE_BYTES
    else:
        family = b"\x00\x02"
        mask = MAGIC_COOKIE_BYTES + transaction_id
    xored = bytes(a ^ b for a, b in zip(packed, mask))
    return family + port_bytes + xored


def mapped_address_value(address: str, port: int) -> bytes:
    """Build a plain MAPPED-ADDRESS attribute value per RFC 8489 §14.1."""
    import ipaddress

    packed = ipaddress.ip_address(address).packed
    family = b"\x00\x01" if len(packed) == 4 else b"\x00\x02"
    return family + struct.pack(">H", port) + packed


def error_code_value(code: int, reason: str) -> bytes:
    class_digit = (code // 100) & 0x07
    number = code % 100
    return b"\x00\x00" + bytes([class_digit, number]) + reason.encode("utf-8")


def pad_attribute_value(value: bytes) -> bytes:
    padding = (-len(value)) % 4
    return value + b"\x00" * padding


def build_attribute(attr_type: int, value: bytes) -> bytes:
    padded = pad_attribute_value(value)
    return struct.pack(">HH", attr_type, len(value)) + padded


def build_message(message_type: int, attributes: list[bytes], transaction_id: bytes = TEST_TRANSACTION_ID) -> bytes:
    body = b"".join(attributes)
    header = struct.pack(">HH", message_type, len(body)) + MAGIC_COOKIE_BYTES + transaction_id
    return header + body


def build_raw(message_type: int, attributes: list[bytes], transaction_id: bytes = TEST_TRANSACTION_ID, body_length: int | None = None) -> bytes:
    """Like build_message but with a controllable declared body length."""
    body = b"".join(attributes)
    declared = len(body) if body_length is None else body_length
    header = struct.pack(">HH", message_type, declared) + MAGIC_COOKIE_BYTES + transaction_id
    return header + body


# ---------------------------------------------------------------------------
# Complete, semantically realistic messages
# ---------------------------------------------------------------------------


def binding_request(software: str = "STUNScope synthetic client", transaction_id: bytes = TEST_TRANSACTION_ID) -> bytes:
    attrs = [build_attribute(ATTR_SOFTWARE, software.encode("utf-8"))]
    return build_message(0x0001, attrs, transaction_id)


def binding_success_response(
    address: str = DOC_IPV4,
    port: int = DOC_IPV4_PORT,
    transaction_id: bytes = TEST_TRANSACTION_ID,
    with_software: bool = True,
) -> bytes:
    """Binding Success Response with XOR-MAPPED-ADDRESS (+ optional SOFTWARE)."""
    attrs = [
        build_attribute(ATTR_XOR_MAPPED_ADDRESS, xor_address_value(address, port, transaction_id))
    ]
    if with_software:
        attrs.append(build_attribute(ATTR_SOFTWARE, b"STUNScope synthetic server v1.0"))
    return build_message(0x0101, attrs, transaction_id)


def binding_success_response_ipv6(transaction_id: bytes = TEST_TRANSACTION_ID) -> bytes:
    return binding_success_response(DOC_IPV6, DOC_IPV6_PORT, transaction_id)


def binding_success_response_plain_mapped(transaction_id: bytes = TEST_TRANSACTION_ID) -> bytes:
    """Binding Success Response using (non-XORed) MAPPED-ADDRESS."""
    attrs = [
        build_attribute(ATTR_MAPPED_ADDRESS, mapped_address_value(DOC_IPV4, DOC_IPV4_PORT))
    ]
    return build_message(0x0101, attrs, transaction_id)


def binding_error_response(
    code: int = 401,
    reason: str = "Unauthorized",
    transaction_id: bytes = TEST_TRANSACTION_ID,
) -> bytes:
    attrs = [
        build_attribute(ATTR_ERROR_CODE, error_code_value(code, reason)),
        build_attribute(ATTR_REALM, b"example.invalid"),
        build_attribute(ATTR_NONCE, b"f6c3a1fe5b2d4e6f"),
    ]
    return build_message(0x0111, attrs, transaction_id)


def binding_indication(transaction_id: bytes = TEST_TRANSACTION_ID) -> bytes:
    return build_message(0x0011, [], transaction_id)


def response_with_message_integrity(transaction_id: bytes = TEST_TRANSACTION_ID) -> bytes:
    """Success response carrying a synthetic (unverifiable) MESSAGE-INTEGRITY."""
    integrity = b"\x2b" * 20  # synthetic HMAC-SHA1 value, never a real credential
    attrs = [
        build_attribute(ATTR_XOR_MAPPED_ADDRESS, xor_address_value(DOC_IPV4, DOC_IPV4_PORT, transaction_id)),
        build_attribute(ATTR_MESSAGE_INTEGRITY, integrity),
        build_attribute(ATTR_FINGERPRINT, b"\x9c\x2d\x21\x42"),
    ]
    return build_message(0x0101, attrs, transaction_id)


def multi_attribute_response(transaction_id: bytes = TEST_TRANSACTION_ID) -> bytes:
    """Success response with several attributes, including a padded USERNAME."""
    attrs = [
        build_attribute(ATTR_USERNAME, b"abcde"),  # 5 bytes → 3 padding bytes
        build_attribute(ATTR_XOR_MAPPED_ADDRESS, xor_address_value(DOC_IPV4, DOC_IPV4_PORT, transaction_id)),
        build_attribute(ATTR_SOFTWARE, b"STUNScope synthetic server v1.0"),
    ]
    return build_message(0x0101, attrs, transaction_id)


def unknown_attribute_message(comprehension_required: bool = True) -> bytes:
    """Message containing an attribute type outside the registry."""
    attr_type = 0x7FFE if comprehension_required else 0xBFFF
    attrs = [build_attribute(attr_type, b"\xde\xad\xbe\xef")]
    return build_message(0x0001, attrs)


# ---------------------------------------------------------------------------
# Hand-computed reference values (independent of stunscope code)
# ---------------------------------------------------------------------------
# These were derived by hand from RFC 8489 so tests validate the decoder
# against the standard rather than against another implementation.

# IPv4: 192.0.2.34:4660 with the fixed transaction ID.
#  Layout: zero byte, family (0x01), port, xored address.
#  port ^ 0x2112 = 0x3326 ; 0xC0000222 ^ 0x2112A442 = 0xE112A660
HAND_IPV4_XOR_VALUE = bytes.fromhex("00013326e112a660")

# IPv6: 2001:db8:1234:5678:11:2233:4455:6666, port 0x5678.
#  port ^ 0x2112 = 0x776A ; address ^ (cookie||transaction) as computed by hand
HAND_IPV6_XOR_VALUE = bytes.fromhex(
    "0002"
    "776a"
    "0113a9fa1225744b44444444ccccccdd"
)
