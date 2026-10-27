"""CSV exporter tests: rows, quoting, redaction, atomicity."""

from __future__ import annotations

import csv
import struct
from pathlib import Path

from fixtures.stun_messages import (
    DOC_IPV4,
    DOC_IPV4_PORT,
    TEST_TRANSACTION_ID,
    binding_error_response,
    binding_request,
    binding_success_response,
    binding_success_response_ipv6,
    multi_attribute_response,
)
from stunscope.capture import build_record
from stunscope.exporter import (
    CSV_COLUMNS,
    export_csv,
    format_timestamp,
    redact_ip,
    record_rows,
)
from stunscope.filters import PacketFilter
from stunscope.models import NOT_AVAILABLE


def make_record(payload: bytes, timestamp=1760000000.0, src_ip="192.0.2.10",
                src_port=50000, dst_ip="198.51.100.20", dst_port=3478):
    record = build_record(
        src_ip, src_port, dst_ip, dst_port, payload,
        interface="test0", timestamp=timestamp,
    )
    assert record is not None
    return record


def read_csv(path: Path) -> list[list[str]]:
    with open(path, encoding="utf-8", newline="") as handle:
        return list(csv.reader(handle))


class TestRowModel:
    def test_one_row_per_attribute(self):
        record = make_record(multi_attribute_response())
        rows = record_rows(record)
        assert len(rows) == 3
        names = [row[CSV_COLUMNS.index("attribute_name")] for row in rows]
        assert names == ["USERNAME", "XOR-MAPPED-ADDRESS", "SOFTWARE"]

    def test_message_without_attributes_yields_one_row(self):
        record = make_record(binding_request())
        header = struct.pack(">HH", 0x0001, 0) + b"\x21\x12\xa4\x42" + TEST_TRANSACTION_ID
        record = make_record(header)
        rows = record_rows(record)
        assert len(rows) == 1
        assert rows[0][CSV_COLUMNS.index("attribute_name")] == NOT_AVAILABLE

    def test_packet_metadata_repeated_on_each_row(self):
        record = make_record(multi_attribute_response())
        rows = record_rows(record)
        timestamp_index = CSV_COLUMNS.index("timestamp")
        txn_index = CSV_COLUMNS.index("transaction_id")
        for row in rows:
            assert row[timestamp_index] == format_timestamp(record.timestamp)
            assert row[txn_index] == record.transaction_id()

    def test_mapped_address_columns_populated(self):
        record = make_record(binding_success_response())
        rows = record_rows(record)
        xor_index = CSV_COLUMNS.index("xor_mapped_address")
        port_index = CSV_COLUMNS.index("mapped_port")
        for row in rows:
            assert row[xor_index] == f"{DOC_IPV4}:{DOC_IPV4_PORT}"
            assert row[port_index] == str(DOC_IPV4_PORT)

    def test_unavailable_vs_empty(self):
        """Absent fields are 'n/a'; empty values stay empty strings."""
        record = make_record(binding_request())
        header = struct.pack(">HH", 0x0001, 0) + b"\x21\x12\xa4\x42" + TEST_TRANSACTION_ID
        record = make_record(header)
        row = record_rows(record)[0]
        by_name = dict(zip(CSV_COLUMNS, row))
        assert by_name["attribute_name"] == NOT_AVAILABLE
        assert by_name["mapped_address"] == NOT_AVAILABLE
        assert by_name["xor_mapped_address"] == NOT_AVAILABLE
        assert by_name["error_or_warning"] == ""  # exists, genuinely empty

    def test_malformed_note_exported(self):
        bad = struct.pack(">HH", 0x0001, 9) + b"\x21\x12\xa4\x42" + b"\x00" * 12 + b"\x00" * 9
        record = make_record(bad)
        assert record.parse_status == "malformed"
        row = record_rows(record)[0]
        by_name = dict(zip(CSV_COLUMNS, row))
        assert by_name["parse_status"] == "malformed"
        assert "multiple of 4" in by_name["error_or_warning"]
        assert by_name["message_method"] == NOT_AVAILABLE


class TestCsvEscaping:
    def test_roundtrip_preserves_values(self, tmp_path: Path):
        record = make_record(multi_attribute_response())
        destination = tmp_path / "escaped.csv"
        assert export_csv([record], destination).success
        data = read_csv(destination)
        assert data[0] == CSV_COLUMNS
        software_row = data[3]
        assert software_row[CSV_COLUMNS.index("attribute_value")] == "STUNScope synthetic server v1.0"

    def test_quote_and_comma_in_attribute_value(self, tmp_path: Path):
        from stunscope.models import StunAttribute, StunMessage

        message = StunMessage(
            valid=True,
            message_type=0x0101,
            message_type_hex="0x0101",
            method=1,
            method_name="Binding",
            message_class="Success Response",
            message_length=8,
            transaction_id="00" * 12,
            attributes=[
                StunAttribute(
                    type=0x8022,
                    type_name="SOFTWARE",
                    length=17,
                    raw=b"a,b \"c\" d",
                    decoded={"value": 'a,b "c" d'},
                )
            ],
        )
        record = make_record(binding_success_response())
        record.message = message
        destination = tmp_path / "quoted.csv"
        assert export_csv([record], destination).success
        row = read_csv(destination)[1]
        assert row[CSV_COLUMNS.index("attribute_value")] == 'a,b "c" d'


class TestRedaction:
    def test_ipv4_redaction(self):
        assert redact_ip("192.0.2.34") == "192.0.2.0/24"
        assert redact_ip("203.0.113.7") == "203.0.113.0/24"

    def test_ipv6_redaction(self):
        assert redact_ip("2001:db8:1234:5678:11:2233:4455:6666") == "2001:db8:1234:5678::/64"
        assert redact_ip("2001:db8::20") == "2001:db8::/64"

    def test_garbage_is_never_leaked(self):
        assert redact_ip("not-an-ip") == "redacted"
        assert redact_ip("") == ""

    def test_export_redacts_addresses(self, tmp_path: Path):
        record = make_record(binding_success_response())
        destination = tmp_path / "redacted.csv"
        result = export_csv([record], destination, redact_addresses=True)
        assert result.success
        row = read_csv(destination)[1]
        by_name = dict(zip(CSV_COLUMNS, row))
        assert by_name["src_ip"] == "192.0.2.0/24"
        assert by_name["dst_ip"] == "198.51.100.0/24"
        assert by_name["xor_mapped_address"] == "192.0.2.0/24:4660"
        # Ports and transaction IDs are not addresses; they are retained.
        assert by_name["src_port"] == "50000"
        assert by_name["mapped_port"] == "4660"
        assert by_name["transaction_id"] == record.transaction_id()

    def test_ipv6_export_redacts_to_slash_64(self, tmp_path: Path):
        record = make_record(binding_success_response_ipv6(), src_ip="2001:db8::20", dst_ip="2001:db8::10")
        destination = tmp_path / "redacted6.csv"
        assert export_csv([record], destination, redact_addresses=True).success
        row = read_csv(destination)[1]
        by_name = dict(zip(CSV_COLUMNS, row))
        assert by_name["src_ip"] == "2001:db8::/64"
        assert by_name["xor_mapped_address"].startswith("2001:db8:1234:")


class TestExportBehavior:
    def test_export_writes_header_and_rows(self, tmp_path: Path):
        records = [
            make_record(binding_request()),
            make_record(binding_success_response()),
            make_record(binding_error_response()),
        ]
        destination = tmp_path / "out.csv"
        result = export_csv(records, destination)
        assert result.success
        assert result.packet_count == 3
        data = read_csv(destination)
        assert data[0] == CSV_COLUMNS
        assert len(data) == 1 + result.rows_written
        assert result.rows_written == 1 + 2 + 3  # SOFTWARE, XOR+SOFTWARE, ERROR+REALM+NONCE

    def test_export_with_packet_filter(self, tmp_path: Path):
        records = [
            make_record(binding_request(), src_ip="192.0.2.10"),
            make_record(binding_success_response(), src_ip="198.51.100.20"),
        ]
        destination = tmp_path / "filtered.csv"
        result = export_csv(
            records, destination, packet_filter=PacketFilter(src_ip="198.51.100.20")
        )
        assert result.success
        assert result.packet_count == 1
        data = read_csv(destination)
        assert len(data) == 3  # header + two attribute rows

    def test_missing_directory_fails_cleanly(self, tmp_path: Path):
        destination = tmp_path / "no-such-dir" / "out.csv"
        result = export_csv([make_record(binding_request())], destination)
        assert not result.success
        assert "does not exist" in result.error
        assert not destination.exists()

    def test_interrupted_export_leaves_no_partial_file(self, tmp_path: Path, monkeypatch):
        destination = tmp_path / "target.csv"
        # Pre-existing content that must survive a failed export.
        destination.write_text("previous content\n", encoding="utf-8")

        def explode(record, redact_addresses=False):
            raise RuntimeError("simulated interruption")

        monkeypatch.setattr("stunscope.exporter.record_rows", explode)
        result = export_csv([make_record(binding_request())], destination)
        assert not result.success
        assert "unexpected export failure" in result.error
        assert destination.read_text(encoding="utf-8") == "previous content\n"
        leftovers = list(tmp_path.glob("*.tmp"))
        assert leftovers == []

    def test_timestamp_is_utc_iso8601(self):
        # 1760000000 s = 2025-10-09T08:53:20Z (verified by hand).
        assert format_timestamp(1760000000.0) == "2025-10-09T08:53:20.000Z"
