"""Shared CSV exporter used by both the CLI and the GUI.

Row model (one row per attribute):
    Every captured STUN message produces one CSV row per decoded
    attribute, and packets with zero attributes produce a single
    "message row". Packet metadata is repeated on every row so a row is
    always self-describing.

Unavailable vs. empty:
    The literal string ``n/a`` marks a field that does not exist for a
    given row (for example attribute columns on a message row, or the
    MAPPED-ADDRESS columns when the message carries no mapped address).
    An empty string marks a field that exists but is genuinely empty
    (for example an ERROR-CODE with an empty reason phrase).

Privacy:
    ``redact_addresses=True`` masks IPv4 addresses to their /24 network
    (``203.0.113.7`` → ``203.0.113.0/24``) and IPv6 addresses to their
    /64 network (``2001:db8::1`` → ``2001:db8::/64``). Ports and
    transaction IDs are retained because they are not personal addresses;
    see docs/privacy-and-security.md. Exports never leave the machine —
    the exporter writes only to the local filesystem.

Partial-write protection:
    Rows are written to a temporary file next to the destination and
    atomically moved into place on success, so an interrupted export
    never leaves a half-written CSV at the chosen path.
"""

from __future__ import annotations

import csv
import ipaddress
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from stunscope.filters import PacketFilter
from stunscope.models import NOT_AVAILABLE, PacketRecord
from stunscope.parser import (
    ATTR_MAPPED_ADDRESS,
    ATTR_XOR_MAPPED_ADDRESS,
)

CSV_COLUMNS = [
    "timestamp",
    "interface",
    "protocol",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "message_type",
    "message_method",
    "message_class",
    "message_type_label",
    "transaction_id",
    "attribute_name",
    "attribute_type_hex",
    "attribute_length",
    "attribute_value",
    "attribute_raw_hex",
    "mapped_address",
    "xor_mapped_address",
    "mapped_port",
    "address_family",
    "parse_status",
    "error_or_warning",
]

MAX_RAW_HEX_BYTES = 32


@dataclass
class ExportResult:
    """Outcome of a CSV export attempt."""

    path: str
    success: bool
    rows_written: int = 0
    packet_count: int = 0
    error: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.finished_at - self.started_at)


def redact_ip(address: str) -> str:
    """Mask an IP address to its network prefix for privacy exports."""
    if not address:
        return address
    try:
        if ":" in address:
            network = ipaddress.ip_network(f"{address}/64", strict=False)
            return f"{network.network_address}/64"
        network = ipaddress.ip_network(f"{address}/24", strict=False)
        return f"{network.network_address}/24"
    except ValueError:
        return "redacted"


def format_timestamp(timestamp: float) -> str:
    """UTC ISO-8601 with millisecond precision, deterministic in tests."""
    moment = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def record_rows(record: PacketRecord, redact_addresses: bool = False) -> list[list[str]]:
    """Build the CSV rows (one per attribute) for a single record."""
    message = record.message
    redact = redact_addresses

    src_ip = redact_ip(record.src_ip) if redact else record.src_ip
    dst_ip = redact_ip(record.dst_ip) if redact else record.dst_ip

    if message is None:
        raise ValueError("record without a parsed message cannot be exported")

    base: list[str] = [
        format_timestamp(record.timestamp),
        record.interface,
        record.protocol,
        src_ip,
        str(record.src_port),
        dst_ip,
        str(record.dst_port),
        message.message_type_hex if message.message_type_hex else NOT_AVAILABLE,
        message.method_name if message.valid else NOT_AVAILABLE,
        message.message_class if message.valid else NOT_AVAILABLE,
        message.type_label(),
        message.transaction_id,
    ]

    note_parts = [message.error, *message.warnings, record.note]
    note = "; ".join(dict.fromkeys(part for part in note_parts if part))

    mapped_address = NOT_AVAILABLE
    xor_mapped_address = NOT_AVAILABLE
    mapped_port = NOT_AVAILABLE
    address_family = NOT_AVAILABLE
    for attr in message.attributes:
        if attr.decoded and "address" in attr.decoded:
            address = attr.decoded["address"]
            if redact:
                address = redact_ip(address)
            if attr.type == ATTR_MAPPED_ADDRESS:
                mapped_address = f"{address}:{attr.decoded['port']}"
            elif attr.type == ATTR_XOR_MAPPED_ADDRESS:
                xor_mapped_address = f"{address}:{attr.decoded['port']}"
            if mapped_port == NOT_AVAILABLE or attr.type == ATTR_XOR_MAPPED_ADDRESS:
                mapped_port = str(attr.decoded["port"])
                address_family = attr.decoded["family"]

    rows: list[list[str]] = []
    if message.attributes:
        for attr in message.attributes:
            value = attr.summary()
            if value.startswith(f"{attr.type_name}: "):
                value = value[len(attr.type_name) + 2:]
            raw_hex = attr.raw[:MAX_RAW_HEX_BYTES].hex()
            if len(attr.raw) > MAX_RAW_HEX_BYTES:
                raw_hex += "…"
            rows.append(base + [
                attr.type_name,
                f"0x{attr.type:04X}",
                str(attr.length),
                value,
                raw_hex,
                mapped_address,
                xor_mapped_address,
                mapped_port,
                address_family,
                record.parse_status,
                note or "",
            ])
    else:
        rows.append(base + [
            NOT_AVAILABLE,  # attribute_name: message-level row
            NOT_AVAILABLE,
            NOT_AVAILABLE,
            NOT_AVAILABLE,
            NOT_AVAILABLE,
            mapped_address,
            xor_mapped_address,
            mapped_port,
            address_family,
            record.parse_status,
            note or "",
        ])
    return rows


def export_csv(
    records: Iterable[PacketRecord],
    path: str | os.PathLike,
    redact_addresses: bool = False,
    packet_filter: Optional[PacketFilter] = None,
) -> ExportResult:
    """Write records to a UTF-8 CSV file atomically.

    ``records`` may be any iterable; when ``packet_filter`` is provided,
    only matching records are exported.
    """
    started = time.time()
    destination = Path(path)
    if destination.parent and not destination.parent.exists():
        return ExportResult(
            path=str(destination),
            success=False,
            error=f"destination directory does not exist: {destination.parent}",
            started_at=started,
            finished_at=time.time(),
        )

    tmp_path = destination.with_name(destination.name + ".tmp")
    rows_written = 0
    packet_count = 0
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(CSV_COLUMNS)
            for record in records:
                if packet_filter is not None and not packet_filter.matches(record):
                    continue
                for row in record_rows(record, redact_addresses=redact_addresses):
                    writer.writerow(row)
                    rows_written += 1
                packet_count += 1
        os.replace(tmp_path, destination)
    except OSError as exc:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        return ExportResult(
            path=str(destination),
            success=False,
            error=f"could not write CSV: {exc}",
            started_at=started,
            finished_at=time.time(),
        )
    except Exception as exc:  # malformed record objects should never kill the app
        try:
            tmp_path.unlink()
        except OSError:
            pass
        return ExportResult(
            path=str(destination),
            success=False,
            error=f"unexpected export failure: {exc}",
            started_at=started,
            finished_at=time.time(),
        )

    return ExportResult(
        path=str(destination),
        success=True,
        rows_written=rows_written,
        packet_count=packet_count,
        started_at=started,
        finished_at=time.time(),
    )
