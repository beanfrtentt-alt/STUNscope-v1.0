"""XOR-MAPPED-ADDRESS decoding tests (RFC 8489 section 14.2).

The expected byte values below were computed *by hand* from the RFC so
these tests validate the decoder against the standard itself:

IPv4 (192.0.2.34:4660, any transaction ID):
    port  0x1234 ^ 0x2112                 = 0x3326
    addr  0xC0000222 ^ 0x2112A442         = 0xE112A660
    attribute value = 00 01 | 33 26 | E1 12 A6 60

IPv6 is covered in test_ipv6.py.
"""

from __future__ import annotations

import struct

from fixtures.stun_messages import (
    DOC_IPV4,
    DOC_IPV4_PORT,
    HAND_IPV4_XOR_VALUE,
    TEST_TRANSACTION_ID,
    binding_success_response,
    binding_success_response_plain_mapped,
    response_with_message_integrity,
    xor_address_value,
)
from stunscope.models import ATTRIBUTE_OK
from stunscope.parser import (
    ATTR_FINGERPRINT,
    ATTR_MAPPED_ADDRESS,
    ATTR_MESSAGE_INTEGRITY,
    ATTR_XOR_MAPPED_ADDRESS,
    parse_stun_message,
)


class TestBuilderVectors:
    """Confirm the fixture builder produces the hand-computed bytes."""

    def test_fixture_value_matches_hand_computation(self):
        value = xor_address_value(DOC_IPV4, DOC_IPV4_PORT, TEST_TRANSACTION_ID)
        assert value == HAND_IPV4_XOR_VALUE
        assert len(value) == 8  # zero, family, port, 4-byte address

    def test_raw_attribute_bytes_encode_xor(self):
        message = parse_stun_message(binding_success_response())
        attr = message.attribute(ATTR_XOR_MAPPED_ADDRESS)
        assert attr is not None
        # The wire bytes must NOT contain the plain port/address.
        assert struct.pack(">H", DOC_IPV4_PORT) not in attr.raw[:4]
        plain_address = bytes.fromhex("c0000222")
        assert plain_address not in attr.raw


class TestIpv4XorDecoding:
    def test_decodes_documentation_address(self):
        message = parse_stun_message(binding_success_response())
        attr = message.attribute(ATTR_XOR_MAPPED_ADDRESS)
        assert attr is not None and attr.decoded is not None
        assert attr.decoded["family"] == "IPv4"
        assert attr.decoded["address"] == DOC_IPV4
        assert attr.decoded["port"] == DOC_IPV4_PORT

    def test_summary_includes_address(self):
        message = parse_stun_message(binding_success_response())
        attr = message.attribute(ATTR_XOR_MAPPED_ADDRESS)
        assert attr is not None
        assert f"{DOC_IPV4}:{DOC_IPV4_PORT}" in attr.summary()

    def test_mapped_address_helper_prefers_xor(self):
        message = parse_stun_message(binding_success_response())
        mapped = message.mapped_address()
        assert mapped is not None
        assert mapped.address == DOC_IPV4
        assert mapped.port == DOC_IPV4_PORT

    def test_attribution_note_present(self):
        message = parse_stun_message(binding_success_response())
        attr = message.attribute(ATTR_XOR_MAPPED_ADDRESS)
        assert attr is not None
        assert "not a" in attr.note and "remote participant" in attr.note

    def test_decode_independent_of_transaction_id(self):
        """IPv4 XOR uses only the magic cookie, so the transaction is irrelevant."""
        other_txn = bytes(range(12))
        message = parse_stun_message(
            binding_success_response(transaction_id=other_txn)
        )
        attr = message.attribute(ATTR_XOR_MAPPED_ADDRESS)
        assert attr is not None and attr.decoded is not None
        assert attr.decoded["address"] == DOC_IPV4


class TestPlainMappedAddress:
    def test_mapped_address_not_xored(self):
        message = parse_stun_message(binding_success_response_plain_mapped())
        attr = message.attribute(ATTR_MAPPED_ADDRESS)
        assert attr is not None and attr.decoded is not None
        assert attr.decoded["address"] == DOC_IPV4
        assert attr.decoded["port"] == DOC_IPV4_PORT
        # No XOR applied: the plain port appears in the raw bytes.
        assert struct.pack(">H", DOC_IPV4_PORT) in attr.raw

    def test_mapped_address_helper_falls_back(self):
        message = parse_stun_message(binding_success_response_plain_mapped())
        mapped = message.mapped_address()
        assert mapped is not None
        assert mapped.address == DOC_IPV4


class TestIntegrityAndFingerprint:
    def test_message_integrity_is_noted_not_verified(self):
        message = parse_stun_message(response_with_message_integrity())
        integrity = message.attribute(ATTR_MESSAGE_INTEGRITY)
        assert integrity is not None
        assert integrity.length == 20
        assert integrity.decoded is not None
        assert "value_hex" in integrity.decoded
        assert "not verified" in integrity.note

    def test_fingerprint_is_noted_not_verified(self):
        message = parse_stun_message(response_with_message_integrity())
        fingerprint = message.attribute(ATTR_FINGERPRINT)
        assert fingerprint is not None
        assert fingerprint.length == 4
        assert fingerprint.decoded is not None
        assert "not verified" in fingerprint.note
        assert fingerprint.decoded["value"] == "0x9C2D2142"

    def test_integrity_message_still_parses_attributes(self):
        message = parse_stun_message(response_with_message_integrity())
        assert message.valid, message.error
        assert message.attribute(ATTR_XOR_MAPPED_ADDRESS) is not None
        assert all(a.status == ATTRIBUTE_OK for a in message.attributes)
