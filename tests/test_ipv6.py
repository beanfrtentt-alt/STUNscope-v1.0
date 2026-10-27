"""IPv6 XOR-MAPPED-ADDRESS decoding tests.

Hand-computed vector (RFC 8489 section 14.2, transaction ID
``00112233445566778899aabb``):

    address 2001:db8:1234:5678:11:2233:4455:6666
    mask   =  2112:a442 followed by the 96-bit transaction ID
    port   0x5678 ^ 0x2112 = 0x776A
    xored address bytes (see HAND_IPV6_XOR_VALUE) =
        01 13 A9 FA 12 25 74 4B 44 44 44 44 CC CC CC DD
"""

from __future__ import annotations

import struct

from fixtures.stun_messages import (
    DOC_IPV6,
    DOC_IPV6_PORT,
    HAND_IPV6_XOR_VALUE,
    TEST_TRANSACTION_ID,
    binding_success_response_ipv6,
    xor_address_value,
)
from stunscope.parser import (
    ATTR_XOR_MAPPED_ADDRESS,
    MAGIC_COOKIE_BYTES,
    parse_stun_message,
)


class TestIpv6XorDecoding:
    def test_fixture_value_matches_hand_computation(self):
        value = xor_address_value(DOC_IPV6, DOC_IPV6_PORT, TEST_TRANSACTION_ID)
        assert value == HAND_IPV6_XOR_VALUE
        assert len(value) == 20  # zero, family, port, 16-byte address

    def test_ipv6_address_decodes(self):
        message = parse_stun_message(binding_success_response_ipv6())
        attr = message.attribute(ATTR_XOR_MAPPED_ADDRESS)
        assert attr is not None and attr.decoded is not None
        assert attr.decoded["family"] == "IPv6"
        assert attr.decoded["address"] == DOC_IPV6
        assert attr.decoded["port"] == DOC_IPV6_PORT  # 22136

    def test_ipv6_attribute_length_is_20(self):
        message = parse_stun_message(binding_success_response_ipv6())
        attr = message.attribute(ATTR_XOR_MAPPED_ADDRESS)
        assert attr is not None
        assert attr.length == 20

    def test_ipv6_uses_full_128_bit_mask(self):
        """The IPv6 mask must combine the cookie AND the transaction ID."""
        address_bytes = bytes.fromhex("20010db8123456780011223344556666")
        mask = MAGIC_COOKIE_BYTES + TEST_TRANSACTION_ID
        xored = bytes(a ^ b for a, b in zip(address_bytes, mask))
        assert xored == bytes.fromhex("0113a9fa1225744b444444444ccccccdd")
        # ...which is exactly what the wire attribute carries.
        message = parse_stun_message(binding_success_response_ipv6())
        attr = message.attribute(ATTR_XOR_MAPPED_ADDRESS)
        assert attr is not None
        assert attr.raw[4:] == xored

    def test_ipv6_transaction_id_matters(self):
        """Changing the transaction ID changes the encoded IPv6 bytes."""
        other_txn = bytes.fromhex("ffffffffffffffffffffffff")
        message = parse_stun_message(
            binding_success_response_ipv6(transaction_id=other_txn)
        )
        attr = message.attribute(ATTR_XOR_MAPPED_ADDRESS)
        assert attr is not None and attr.decoded is not None
        assert attr.decoded["address"] == DOC_IPV6
        assert attr.decoded["port"] == DOC_IPV6_PORT
        # The raw bytes differ from the fixed-transaction fixture.
        fixed_message = parse_stun_message(binding_success_response_ipv6())
        assert attr.raw != fixed_message.attribute(ATTR_XOR_MAPPED_ADDRESS).raw

    def test_ipv6_plain_port_not_on_wire(self):
        message = parse_stun_message(binding_success_response_ipv6())
        attr = message.attribute(ATTR_XOR_MAPPED_ADDRESS)
        assert attr is not None
        assert struct.pack(">H", DOC_IPV6_PORT) not in attr.raw[:4]
        plain = bytes.fromhex("20010db812345678")
        assert plain not in attr.raw
