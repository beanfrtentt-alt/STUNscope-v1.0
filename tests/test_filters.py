"""PacketFilter tests shared by the CLI and the GUI."""

from __future__ import annotations

import pytest

from fixtures.stun_messages import (
    ALT_TRANSACTION_ID,
    TEST_TRANSACTION_ID,
    binding_error_response,
    binding_request,
    binding_success_response,
    binding_success_response_ipv6,
)
from stunscope.capture import build_record
from stunscope.filters import FilterError, PacketFilter


def make_record(payload: bytes, src_ip="192.0.2.10", src_port=50000,
                dst_ip="198.51.100.20", dst_port=3478, timestamp=1760000000.0):
    record = build_record(
        src_ip, src_port, dst_ip, dst_port, payload,
        interface="test0", timestamp=timestamp,
    )
    assert record is not None, "fixture should look like STUN"
    return record


@pytest.fixture()
def sample_records():
    request = make_record(binding_request())
    success_v4 = make_record(binding_success_response(), src_ip="198.51.100.20", src_port=3478, dst_ip="192.0.2.10", dst_port=50000)
    success_v6 = make_record(binding_success_response_ipv6(), src_ip="2001:db8::20", src_port=3479, dst_ip="2001:db8::10", dst_port=50001)
    error = make_record(binding_error_response(), src_ip="203.0.113.99", src_port=3478, dst_ip="192.0.2.10", dst_port=50000)
    return {"request": request, "success_v4": success_v4, "success_v6": success_v6, "error": error}


class TestMessageTypeFilters:
    def test_binding_request_token(self, sample_records):
        packet_filter = PacketFilter(message_type="binding-request")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert matches == ["request"]

    def test_binding_success_token(self, sample_records):
        packet_filter = PacketFilter(message_type="binding-success")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert sorted(matches) == ["success_v4", "success_v6"]

    def test_binding_error_token(self, sample_records):
        packet_filter = PacketFilter(message_type="binding-error")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert matches == ["error"]

    def test_class_token_success(self, sample_records):
        packet_filter = PacketFilter(message_type="success")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert sorted(matches) == ["success_v4", "success_v6"]

    def test_class_token_error(self, sample_records):
        packet_filter = PacketFilter(message_type="error")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert matches == ["error"]

    def test_binding_token_matches_all_binding(self, sample_records):
        packet_filter = PacketFilter(message_type="binding")
        assert all(packet_filter.matches(r) for r in sample_records.values())

    def test_hex_type_token(self, sample_records):
        packet_filter = PacketFilter(message_type="0x0111")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert matches == ["error"]

    def test_case_insensitive_token(self, sample_records):
        assert PacketFilter(message_type="Binding-Request").matches(sample_records["request"])

    def test_unknown_token_raises(self):
        with pytest.raises(FilterError):
            PacketFilter(message_type="not-a-type")
        with pytest.raises(FilterError):
            PacketFilter(message_type="0x10000")


class TestIpFilters:
    def test_src_exact(self, sample_records):
        packet_filter = PacketFilter(src_ip="198.51.100.20")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert matches == ["success_v4"]

    def test_dst_exact(self, sample_records):
        packet_filter = PacketFilter(dst_ip="192.0.2.10")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert sorted(matches) == ["request", "success_v4", "error"]

    def test_cidr_prefix(self, sample_records):
        packet_filter = PacketFilter(src_ip="198.51.100.0/24")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert matches == ["success_v4"]

    def test_wildcard_suffix(self, sample_records):
        packet_filter = PacketFilter(src_ip="2001:db8::*")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert matches == ["success_v6"]

    def test_both_directions(self, sample_records):
        packet_filter = PacketFilter(src_ip="203.0.113.99", dst_ip="192.0.2.10")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert matches == ["error"]


class TestTransactionFilters:
    def test_full_transaction_id(self, sample_records):
        packet_filter = PacketFilter(transaction_id=TEST_TRANSACTION_ID.hex())
        assert all(packet_filter.matches(r) for r in sample_records.values())

    def test_prefix_transaction_id(self, sample_records):
        other = make_record(
            binding_request(transaction_id=ALT_TRANSACTION_ID),
            src_ip="203.0.113.5", dst_ip="203.0.113.9",
        )
        packet_filter = PacketFilter(transaction_id=ALT_TRANSACTION_ID.hex()[:8])
        assert packet_filter.matches(other)
        assert not any(packet_filter.matches(r) for r in sample_records.values())

    def test_dashes_and_case_ignored(self, sample_records):
        dashed = "-".join(TEST_TRANSACTION_ID.hex()[i:i + 4] for i in range(0, 24, 4))
        upper = TEST_TRANSACTION_ID.hex().upper()
        packet_filter = PacketFilter(transaction_id=dashed)
        assert all(packet_filter.matches(r) for r in sample_records.values())
        assert all(PacketFilter(transaction_id=upper).matches(r) for r in sample_records.values())


class TestValidityFilters:
    def test_malformed_only(self):
        import struct

        bad = make_record(struct.pack(">HH", 0x0001, 40) + b"\x21\x12\xa4\x42" + b"\x00" * 12)
        good = make_record(binding_request(), dst_ip="198.51.100.7")
        assert bad.parse_status == "malformed"
        malformed_filter = PacketFilter(validity="malformed")
        valid_filter = PacketFilter(validity="valid")
        assert malformed_filter.matches(bad) and not malformed_filter.matches(good)
        assert valid_filter.matches(good) and not valid_filter.matches(bad)

    def test_any_matches_everything(self, sample_records):
        packet_filter = PacketFilter(validity="any")
        assert all(packet_filter.matches(r) for r in sample_records.values())

    def test_bad_validity_raises(self):
        with pytest.raises(FilterError):
            PacketFilter(validity="broken")


class TestSearchAndCombination:
    def test_search_by_attribute_text(self, sample_records):
        packet_filter = PacketFilter(search="Unauthorized")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert matches == ["error"]

    def test_search_by_ip(self, sample_records):
        packet_filter = PacketFilter(search="203.0.113.99")
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert matches == ["error"]

    def test_combined_filters(self, sample_records):
        packet_filter = PacketFilter(
            message_type="success",
            dst_ip="192.0.2.10",
        )
        matches = [k for k, r in sample_records.items() if packet_filter.matches(r)]
        assert matches == ["success_v4"]

    def test_is_active_and_describe(self):
        assert not PacketFilter().is_active()
        active = PacketFilter(message_type="binding-request", search="x")
        assert active.is_active()
        text = active.describe()
        assert "message type = binding-request" in text
        assert "search = 'x'" in text
        assert PacketFilter().describe() == "no active filters"
