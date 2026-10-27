"""CLI tests: help, argument validation, offline parsing, CSV export.

These tests deliberately avoid live capture: they use the offline
``parse-file`` command, synthetic fixtures, and the environment error
paths. They require neither Npcap nor Administrator privileges.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from fixtures.stun_messages import (
    TEST_TRANSACTION_ID,
    binding_error_response,
    binding_request,
    binding_success_response,
)
from stunscope.cli import main
from stunscope.exporter import CSV_COLUMNS


def write_fixture_file(path: Path) -> Path:
    lines = [
        "# Synthetic STUN fixtures (documentation address ranges only).",
        binding_request().hex(),
        binding_success_response().hex(),
        f"192.0.2.55:40000->198.51.100.20:3478 {binding_error_response().hex()}",
        "this-line-is-not-hex-and-should-be-skipped",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class TestHelpAndVersion:
    def test_help_shows_commands(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        assert "list-interfaces" in out
        assert "capture" in out
        assert "parse-file" in out
        assert "gui" in out

    def test_version_prints_stunscope(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--version"])
        assert excinfo.value.code == 0
        assert "STUNScope 1.0.0" in capsys.readouterr().out

    def test_no_command_prints_help_and_returns_usage(self, capsys):
        assert main([]) == 2
        out = capsys.readouterr().out
        assert "usage:" in out.lower() or "COMMAND" in out

    def test_unknown_command_exits_with_error(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["not-a-command"])
        assert excinfo.value.code == 2

    def test_info_reports_environment(self, capsys):
        assert main(["info"]) == 0
        out = capsys.readouterr().out
        assert "STUNScope 1.0.0" in out
        assert "Scapy:" in out
        assert "PySide6:" in out


class TestParseFile:
    def test_parse_file_decodes_messages(self, tmp_path: Path, capsys):
        fixture = write_fixture_file(tmp_path / "fixtures.txt")
        assert main(["parse-file", str(fixture)]) == 0
        out = capsys.readouterr().out
        assert "Binding Request" in out
        assert "Binding Success Response" in out
        assert "Binding Error Response" in out
        assert "skipped" in out  # the non-hex line was reported
        assert "Parsed 3 STUN message(s)" in out

    def test_parse_file_verbose_details(self, tmp_path: Path, capsys):
        fixture = write_fixture_file(tmp_path / "fixtures.txt")
        assert main(["parse-file", str(fixture), "--verbose"]) == 0
        out = capsys.readouterr().out
        assert "Transaction ID:" in out
        assert "XOR-MAPPED-ADDRESS" in out
        assert "401 Unauthorized" in out  # ERROR-CODE decoded in verbose mode

    def test_parse_file_missing_path_fails(self, capsys):
        assert main(["parse-file", str(Path("does-not-exist.txt"))]) == 2
        assert "not found" in capsys.readouterr().err

    def test_parse_file_respects_endpoint_headers(self, tmp_path: Path, capsys):
        fixture = write_fixture_file(tmp_path / "fixtures.txt")
        assert main(["parse-file", str(fixture), "--src", "192.0.2.55"]) == 0
        out = capsys.readouterr().out
        assert "Binding Error Response" in out
        assert "Binding Request" not in out

    def test_parse_file_message_type_filter(self, tmp_path: Path, capsys):
        fixture = write_fixture_file(tmp_path / "fixtures.txt")
        assert main(["parse-file", str(fixture), "--message-type", "binding-request"]) == 0
        out = capsys.readouterr().out
        assert "Binding Request" in out
        assert "Binding Success Response" not in out

    def test_parse_file_transaction_filter(self, tmp_path: Path, capsys):
        fixture = write_fixture_file(tmp_path / "fixtures.txt")
        txn = TEST_TRANSACTION_ID.hex()
        assert main(["parse-file", str(fixture), "--transaction-id", txn[:12]]) == 0
        out = capsys.readouterr().out
        assert "Binding Request" in out

    def test_bad_filter_token_is_rejected(self, tmp_path: Path, capsys):
        fixture = write_fixture_file(tmp_path / "fixtures.txt")
        assert main(["parse-file", str(fixture), "--message-type", "nope"]) == 2
        assert "unknown message type" in capsys.readouterr().err


class TestCsvExportFromCli:
    def test_parse_file_csv_export(self, tmp_path: Path, capsys):
        fixture = write_fixture_file(tmp_path / "fixtures.txt")
        destination = tmp_path / "export.csv"
        assert main(["parse-file", str(fixture), "--csv", str(destination)]) == 0
        assert destination.exists()
        with open(destination, encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle))
        assert rows[0] == CSV_COLUMNS
        # request(1 attr) + success(2 attrs) + error(3 attrs) = 6 rows
        assert len(rows) == 7
        out = capsys.readouterr().out
        assert "Exported 6 CSV rows for 3 packets" in out

    def test_csv_export_respects_filters(self, tmp_path: Path):
        fixture = write_fixture_file(tmp_path / "fixtures.txt")
        destination = tmp_path / "filtered.csv"
        assert (
            main(
                [
                    "parse-file",
                    str(fixture),
                    "--message-type",
                    "binding-error",
                    "--csv",
                    str(destination),
                ]
            )
            == 0
        )
        with open(destination, encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle))
        # header + ERROR-CODE + REALM + NONCE
        assert len(rows) == 4
        attribute_column = CSV_COLUMNS.index("attribute_name")
        assert rows[1][attribute_column] == "ERROR-CODE"

    def test_csv_redaction_flag(self, tmp_path: Path):
        fixture = write_fixture_file(tmp_path / "fixtures.txt")
        destination = tmp_path / "redacted.csv"
        assert main(["parse-file", str(fixture), "--csv", str(destination), "--redact"]) == 0
        with open(destination, encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle))
        src_column = CSV_COLUMNS.index("src_ip")
        assert rows[1][src_column] == "192.0.2.0/24"


class TestCaptureErrors:
    def test_capture_with_unknown_interface_fails_gracefully(self, capsys):
        # Without a matching device (and without Npcap in CI) the command
        # must return the usage exit code with a readable error.
        code = main(["capture", "--interface", "definitely-not-a-device"])
        assert code == 2
        err = capsys.readouterr().err
        assert "error" in err.lower()

    def test_capture_requires_interface_argument(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["capture"])
        assert excinfo.value.code == 2

    def test_invalid_duration_is_rejected(self, capsys):
        with pytest.raises(SystemExit):
            main(["capture", "-i", "x", "--duration", "abc"])
        err = capsys.readouterr().err
        assert "invalid" in err.lower()

    def test_list_interfaces_never_raises(self, capsys):
        code = main(["list-interfaces"])
        assert code in (0, 2)  # 0 with devices, 2 without Scapy/Npcap
