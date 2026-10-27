"""RFC 8489 core parser tests using synthetic fixtures."""

from __future__ import annotations

import struct

import pytest

from fixtures.stun_messages import (
    ALT_TRANSACTION_ID,
    ALT_TRANSACTION_HEX,
    TEST_TRANSACTION_HEX,
    TEST_TRANSACTION_ID,
    binding_error_response,
    binding_indication,
    binding_request,
    binding_success_response,
    multi_attribute_response,
    unknown_attribute_message,
)
from stunscope.models import ATTRIBUTE_OK, ATTRIBUTE_UNSUPPORTED
from stunscope.parser import (
    ATTR_SOFTWARE,
    ATTR_USERNAME,
    decode_message_type,
    looks_like_stun,
    message_type_label,
    maybe_stun,
    parse_stun_message,
)


class TestBindingRequest:
    def test_basic_request_parses(self):
        data = binding_request()
        message = parse_stun_message(data)
        assert message.valid, message.error
        assert message.message_type == 0x0001
        assert message.message_type_hex == "0x0001"
        assert message.message_class == "Request"
        assert message.method_name == "Binding"
        assert message.method == 0x001
        assert message.transaction_id == TEST_TRANSACTION_HEX

    def test_request_software_attribute_decoded(self):
        message = parse_stun_message(binding_request())
        software = message.attribute(ATTR_SOFTWARE)
        assert software is not None
        assert software.status == ATTRIBUTE_OK
        assert software.decoded is not None
        assert software.decoded["value"] == "STUNScope synthetic client"
        # "STUNScope synthetic client" is 26 bytes -> declared length 26,
        # padded to 28 -> attribute occupies 32 bytes of body.
        assert software.length == 26
        assert message.message_length == 32

    def test_bare_request_has_no_attributes(self):
        # A request with no attributes: declared length 0, body empty.
        header = struct.pack(">HH", 0x0001, 0) + b"\x21\x12\xa4\x42" + TEST_TRANSACTION_ID
        message = parse_stun_message(header)
        assert message.valid
        assert message.message_length == 0
        assert message.attributes == []


class TestBindingSuccess:
    def test_success_response_header(self):
        message = parse_stun_message(binding_success_response())
        assert message.valid, message.error
        assert message.message_type == 0x0101
        assert message.message_class == "Success Response"
        assert message.method_name == "Binding"
        assert message.is_binding_success()
        assert not message.is_binding_request()

    def test_success_response_attributes_present(self):
        message = parse_stun_message(binding_success_response())
        types = {attr.type for attr in message.attributes}
        assert 0x0020 in types  # XOR-MAPPED-ADDRESS
        assert 0x8022 in types  # SOFTWARE
        assert len(message.attributes) == 2


class TestBindingError:
    def test_error_response_header(self):
        message = parse_stun_message(binding_error_response())
        assert message.valid, message.error
        assert message.message_type == 0x0111
        assert message.message_class == "Error Response"
        assert message.is_binding_error()

    def test_error_code_decoded(self):
        message = parse_stun_message(binding_error_response())
        error = message.attribute(0x0009)
        assert error is not None
        assert error.decoded is not None
        assert error.decoded["code"] == 401
        assert error.decoded["reason"] == "Unauthorized"
        assert message.error_code() == 401

    def test_realm_and_nonce_decoded(self):
        message = parse_stun_message(binding_error_response())
        realm = message.attribute(0x0014)
        nonce = message.attribute(0x0015)
        assert realm is not None and realm.decoded["value"] == "example.invalid"
        assert nonce is not None and nonce.decoded["value"] == "f6c3a1fe5b2d4e6f"


class TestTransactionId:
    def test_transaction_id_extraction(self):
        message = parse_stun_message(binding_request())
        assert message.transaction_id == TEST_TRANSACTION_ID.hex()
        assert len(message.transaction_id) == 24
        assert message.transaction_id_bytes == TEST_TRANSACTION_ID

    def test_alternate_transaction_id(self):
        message = parse_stun_message(
            binding_request(transaction_id=ALT_TRANSACTION_ID)
        )
        assert message.valid
        assert message.transaction_id == ALT_TRANSACTION_HEX
        assert message.transaction_id != TEST_TRANSACTION_HEX


class TestMultipleAttributesAndPadding:
    def test_multiple_attributes_in_one_message(self):
        message = parse_stun_message(multi_attribute_response())
        assert message.valid, message.error
        assert len(message.attributes) == 3
        names = [attr.type_name for attr in message.attributes]
        assert names == ["USERNAME", "XOR-MAPPED-ADDRESS", "SOFTWARE"]

    def test_attribute_padding_between_attributes(self):
        # USERNAME value is 5 bytes → 3 padding bytes must be consumed and
        # the following XOR-MAPPED-ADDRESS must still parse at the right
        # offset.
        message = parse_stun_message(multi_attribute_response())
        username = message.attributes[0]
        xor_mapped = message.attributes[1]
        assert username.type == ATTR_USERNAME
        assert username.length == 5
        assert username.decoded is not None
        assert username.decoded["value"] == "abcde"
        assert xor_mapped.type == 0x0020
        assert xor_mapped.decoded is not None
        assert xor_mapped.decoded["port"] == 0x1234
        # 4 + 5 + 3 (padding) + 12 = 24 bytes consumed through the second
        # attribute; the SOFTWARE attribute (36 bytes) completes the body.
        assert message.message_length == 24 + 36

    def test_trailing_bytes_produce_warning_not_error(self):
        data = binding_request() + b"\xde\xad\xbe\xef"
        assert looks_like_stun(data)
        message = parse_stun_message(data)
        assert message.valid
        assert any("trailing bytes" in warning for warning in message.warnings)


class TestMessageTypeDecoding:
    @pytest.mark.parametrize(
        ("raw_type", "method", "class_code"),
        [
            (0x0001, 0x001, 0),  # Binding Request
            (0x0011, 0x001, 1),  # Binding Indication
            (0x0101, 0x001, 2),  # Binding Success Response
            (0x0111, 0x001, 3),  # Binding Error Response
            (0x0003, 0x003, 0),  # TURN Allocate Request
            (0x0016, 0x006, 1),  # TURN Send Indication
            (0x0113, 0x003, 3),  # TURN Allocate Error Response
        ],
    )
    def test_decode_message_type(self, raw_type, method, class_code):
        assert decode_message_type(raw_type) == (method, class_code)

    def test_message_type_labels(self):
        assert message_type_label(0x0001) == "Binding Request"
        assert message_type_label(0x0101) == "Binding Success Response"
        assert message_type_label(0x0111) == "Binding Error Response"


class TestDetectionHelpers:
    def test_looks_like_stun_accepts_valid_message(self):
        assert looks_like_stun(binding_success_response())

    def test_looks_like_stun_rejects_non_stun(self):
        assert not looks_like_stun(b"")
        assert not looks_like_stun(b"\x00" * 12)
        assert not looks_like_stun(b"GET /index.html HTTP/1.1\r\n\r\n")
        assert not looks_like_stun(b"\xff" + b"\x00" * 30)

    def test_maybe_stun_is_looser_for_capture(self):
        # Wrong body length is still plausibly STUN (magic + framing bits)
        # so the capture layer can surface malformed messages.
        bad_length = (
            struct.pack(">HH", 0x0001, 3)  # 3 is not a multiple of 4
            + b"\x21\x12\xa4\x42"
            + b"\x00" * 12
        )
        assert maybe_stun(bad_length)
        assert not looks_like_stun(bad_length)
        message = parse_stun_message(bad_length)
        assert not message.valid
        assert "multiple of 4" in message.error


class TestUnknownAttributes:
    def test_unknown_comprehension_required_is_flagged(self):
        message = parse_stun_message(unknown_attribute_message(comprehension_required=True))
        attr = message.attributes[0]
        assert attr.status == ATTRIBUTE_UNSUPPORTED
        assert attr.decoded is None
        assert "comprehension-required" in attr.note
        assert any("comprehension-required" in w for w in message.warnings)

    def test_unknown_comprehension_optional_has_no_warning(self):
        message = parse_stun_message(unknown_attribute_message(comprehension_required=False))
        assert message.valid
        attr = message.attributes[0]
        assert attr.status == ATTRIBUTE_UNSUPPORTED
        assert message.warnings == []

    def test_binding_indication_with_empty_body(self):
        message = parse_stun_message(binding_indication())
        assert message.valid
        assert message.message_class == "Indication"
        assert message.attributes == []
