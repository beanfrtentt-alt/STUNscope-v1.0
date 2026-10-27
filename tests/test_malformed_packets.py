"""Malformed packets must produce readable diagnostics, never exceptions."""

from __future__ import annotations

import random
import struct

from fixtures.stun_messages import (
    TEST_TRANSACTION_ID,
    build_attribute,
    build_message,
    build_raw,
)
from stunscope.models import (
    ATTRIBUTE_MALFORMED,
    PARSE_MALFORMED,
    PARSE_OK,
)
from stunscope.parser import (
    ATTR_ERROR_CODE,
    ATTR_MAPPED_ADDRESS,
    ATTR_MESSAGE_INTEGRITY,
    ATTR_USERNAME,
    parse_stun_message,
)


def _header(message_type: int, body_length: int) -> bytes:
    return (
        struct.pack(">HH", message_type, body_length)
        + b"\x21\x12\xa4\x42"
        + TEST_TRANSACTION_ID
    )


class TestHeaderViolations:
    def test_empty_payload(self):
        message = parse_stun_message(b"")
        assert not message.valid
        assert "empty payload" in message.error
        assert message.attributes == []

    def test_truncated_header(self):
        message = parse_stun_message(_header(0x0001, 0)[:10])
        assert not message.valid
        assert "truncated header" in message.error
        assert "10" in message.error and "20" in message.error

    def test_wrong_magic_cookie(self):
        data = (
            struct.pack(">HH", 0x0001, 0)
            + b"\x12\x34\x56\x78"
            + TEST_TRANSACTION_ID
        )
        message = parse_stun_message(data)
        assert not message.valid
        assert "magic cookie" in message.error

    def test_first_two_bits_must_be_zero(self):
        data = (
            struct.pack(">HH", 0xC001, 0)
            + b"\x21\x12\xa4\x42"
            + TEST_TRANSACTION_ID
        )
        message = parse_stun_message(data)
        assert not message.valid
        assert "leading bits" in message.error
        assert message.message_type_hex == "0xC001"

    def test_declared_length_larger_than_datagram(self):
        # Header claims a 40-byte body but only 12 bytes follow.
        small_attribute = build_attribute(ATTR_USERNAME, b"user")
        data = _header(0x0001, 40) + small_attribute
        message = parse_stun_message(data)
        assert not message.valid
        assert "truncated message" in message.error

    def test_length_not_multiple_of_four(self):
        data = _header(0x0001, 5) + b"\x00" * 5
        message = parse_stun_message(data)
        assert not message.valid
        assert "multiple of 4" in message.error


class TestAttributeViolations:
    def test_attribute_overruns_message_body(self):
        # Attribute claims 40 value bytes but the body only has 12.
        oversized = struct.pack(">HH", 0x0020, 40) + b"\x00" * 8
        data = build_raw(0x0101, [oversized])
        message = parse_stun_message(data)
        assert not message.valid
        assert "overruns the message body" in message.error

    def test_partial_attributes_are_retained(self):
        good = build_attribute(ATTR_USERNAME, b"user")
        bad = struct.pack(">HH", 0x0020, 999) + b"\x00" * 4
        data = build_message(0x0001, [good, bad])
        message = parse_stun_message(data)
        assert not message.valid
        # The USERNAME parsed before the failure is still available.
        assert len(message.attributes) == 1
        assert message.attributes[0].type == ATTR_USERNAME

    def test_body_shorter_than_attribute_header(self):
        # Declares a 4-byte body but only 2 bytes are present: the header
        # validation catches this first with a readable "truncated" error.
        data = build_raw(0x0001, [b"\x00\x00"], body_length=4)
        message = parse_stun_message(data)
        assert not message.valid
        assert "truncated message" in message.error

    def test_mapped_address_wrong_length(self):
        short = build_attribute(ATTR_MAPPED_ADDRESS, b"\x00\x01\x12\x34\x0a")
        data = build_message(0x0101, [short])
        message = parse_stun_message(data)
        assert not message.valid
        assert "8 bytes" in message.error
        assert message.attributes[0].status == ATTRIBUTE_MALFORMED

    def test_invalid_address_family(self):
        weird = build_attribute(ATTR_MAPPED_ADDRESS, b"\x00\x03\x12\x34\x00\x00\x00\x00")
        data = build_message(0x0101, [weird])
        message = parse_stun_message(data)
        assert not message.valid
        assert "unknown address family 0x03" in message.error

    def test_error_code_too_short(self):
        short = build_attribute(ATTR_ERROR_CODE, b"\x00\x00")
        data = build_message(0x0111, [short])
        message = parse_stun_message(data)
        assert not message.valid
        assert "ERROR-CODE" in message.error

    def test_error_code_outside_300_699_range(self):
        # class digit 1, number 99 → code 199, below the RFC range.
        odd = build_attribute(ATTR_ERROR_CODE, b"\x00\x00\x01\x63bad")
        data = build_message(0x0111, [odd])
        message = parse_stun_message(data)
        # Unusual codes are a warning on the attribute, not a framing error.
        assert message.valid, message.error
        attr = message.attributes[0]
        assert attr.decoded is not None
        assert attr.decoded["code"] == 199
        assert "300-699" in attr.note

    def test_message_integrity_wrong_length(self):
        short = build_attribute(ATTR_MESSAGE_INTEGRITY, b"\x00" * 10)
        data = build_message(0x0001, [short])
        message = parse_stun_message(data)
        assert not message.valid
        assert "MESSAGE-INTEGRITY" in message.error


class TestFuzzRobustness:
    def test_random_bytes_never_raise(self):
        rng = random.Random(20261026)
        for _ in range(250):
            length = rng.randint(0, 60)
            data = bytes(rng.getrandbits(8) for _ in range(length))
            message = parse_stun_message(data)  # must not raise
            assert isinstance(message.valid, bool)
            if not message.valid:
                assert message.error, "invalid messages must explain why"

    def test_random_stun_ish_headers_never_raise(self):
        rng = random.Random(42)
        for _ in range(150):
            body_length = rng.choice([0, 4, 8, 12, 16, 20])
            message_type = rng.randint(0, 0xFFFF) & 0x3FFF
            data = (
                struct.pack(">HH", message_type, body_length)
                + b"\x21\x12\xa4\x42"
                + bytes(rng.getrandbits(8) for _ in range(12))
                + bytes(rng.getrandbits(8) for _ in range(body_length))
            )
            message = parse_stun_message(data)
            if not message.valid:
                assert message.error
            else:
                assert message.message_length == body_length


class TestRecordStatusHelpers:
    def test_parse_status_strings(self):
        from fixtures.stun_messages import binding_request

        valid = parse_stun_message(binding_request())
        assert valid.valid
        assert PARSE_OK == "valid"
        bad = parse_stun_message(b"\x00" * 5)
        assert not bad.valid
        assert PARSE_MALFORMED == "malformed"

    def test_invalid_message_type_label(self):
        bad = parse_stun_message(_header(0xC001, 0))
        assert "Malformed" in bad.type_label()
