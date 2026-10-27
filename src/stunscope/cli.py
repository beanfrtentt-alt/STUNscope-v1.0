"""STUNScope command-line interface.

Usage summary::

    python -m stunscope list-interfaces
    python -m stunscope capture -i <interface> [options]
    python -m stunscope parse-file fixtures.txt [options]
    python -m stunscope gui
    python -m stunscope info

The CLI uses exactly the same parser, filter, and CSV exporter as the
desktop GUI. Live capture requires Scapy plus Npcap on Windows and, on
most interfaces, an elevated (Administrator) terminal. You must have
authorization to inspect the traffic you capture.

Exit codes: 0 success, 1 unexpected error, 2 usage or environment
problems (missing Scapy/Npcap, bad interface, unknown filter).
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Optional

from stunscope import __version__
from stunscope.capture import (
    CaptureError,
    CaptureEngine,
    CaptureInterfaceError,
    CaptureUnavailableError,
    InterfaceInfo,
    COMMON_STUN_PORTS,
    list_interfaces,
    scapy_available,
)
from stunscope.config import config_dir, settings_path
from stunscope.exporter import export_csv
from stunscope.filters import FilterError, PacketFilter
from stunscope.logging_config import setup_logging
from stunscope.models import PARSE_MALFORMED, PacketRecord
from stunscope.parser import (
    describe_stun_message,
    short_transaction_id,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

_BANNER = "STUNScope — STUN packet analyzer (authorized diagnostics only)"


# ---------------------------------------------------------------------------
# Small formatting helpers
# ---------------------------------------------------------------------------


def _timestamp_label(timestamp: float) -> str:
    moment = time.localtime(timestamp)
    return time.strftime("%H:%M:%S", moment) + f".{int((timestamp % 1) * 1000):03d}"


def _format_record_line(record: PacketRecord, verbose: bool) -> str:
    label = _timestamp_label(record.timestamp)
    endpoint = f"{record.src_ip}:{record.src_port} -> {record.dst_ip}:{record.dst_port}"
    message = record.message
    type_label = record.type_label()
    txn = short_transaction_id(record.transaction_id())
    attr_count = len(message.attributes) if message else 0
    line = f"{label}  {endpoint:<47}  {type_label:<28}  txn={txn:<16}  attrs={attr_count}"
    if record.parse_status == PARSE_MALFORMED and record.note:
        line += f"  [{record.note}]"
    if verbose and message is not None:
        details = describe_stun_message(message)
        line += "\n" + "\n".join(f"    | {d}" for d in details)
    return line


def _build_filter_from_args(args) -> PacketFilter:
    return PacketFilter(
        message_type=getattr(args, "message_type", "") or "",
        src_ip=getattr(args, "src", "") or "",
        dst_ip=getattr(args, "dst", "") or "",
        transaction_id=getattr(args, "transaction_id", "") or "",
        validity=getattr(args, "validity", "any") or "any",
        search=getattr(args, "search", "") or "",
    )


def _export_records(records, csv_path: Optional[str], redact: bool, packet_filter: PacketFilter) -> int:
    if not csv_path:
        return EXIT_OK
    destination = Path(csv_path).expanduser()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"error: cannot create export directory: {exc}", file=sys.stderr)
        return EXIT_ERROR
    result = export_csv(records, destination, redact_addresses=redact, packet_filter=packet_filter)
    if result.success:
        print(
            f"Exported {result.rows_written} CSV rows for "
            f"{result.packet_count} packets to {result.path}"
        )
        return EXIT_OK
    print(f"error: {result.error}", file=sys.stderr)
    return EXIT_ERROR


def _print_summary(records, stats=None) -> None:
    valid = sum(1 for r in records if r.parse_status != PARSE_MALFORMED)
    requests = sum(1 for r in records if r.message and r.message.is_binding_request())
    successes = sum(1 for r in records if r.message and r.message.is_binding_success())
    errors = sum(1 for r in records if r.message and r.message.is_binding_error())
    malformed = len(records) - valid
    print()
    print("Capture summary")
    print(f"  STUN messages shown: {len(records)} (valid: {valid}, malformed: {malformed})")
    print(f"  Binding Requests:    {requests}")
    print(f"  Binding Success:     {successes}")
    print(f"  Binding Errors:      {errors}")
    if stats is not None:
        print(
            f"  UDP datagrams seen:  {stats.packets_seen}  "
            f"(duration {stats.duration_seconds:.1f}s)"
        )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _resolve_interface(spec: str) -> InterfaceInfo:
    """Accept a Scapy name, a 1-based index, or a unique description prefix."""
    interfaces = list_interfaces()
    for iface in interfaces:
        if iface.name == spec:
            return iface
    if spec.isdigit():
        index = int(spec)
        if 1 <= index <= len(interfaces):
            return interfaces[index - 1]
    lowered = spec.lower()
    matches = [i for i in interfaces if lowered in i.description.lower()]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise CaptureInterfaceError(
            f"interface spec {spec!r} matches {len(matches)} interfaces; "
            "use the exact name or index from `list-interfaces`"
        )
    raise CaptureInterfaceError(
        f"interface {spec!r} was not found; run `python -m stunscope list-interfaces`"
    )


def _cmd_list_interfaces(args) -> int:
    if not scapy_available():
        print(
            "error: Scapy is not installed, so interfaces cannot be listed.\n"
            "       Install the dependencies first:  pip install -r requirements.txt\n"
            "       See docs/installation-windows.md for the Windows setup.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        interfaces = list_interfaces()
    except CaptureUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print("Available capture interfaces:")
    print()
    for index, iface in enumerate(interfaces, start=1):
        print(f"  {index}. {iface.description}")
        print(f"       name:      {iface.name}")
        if iface.addresses:
            print(f"       addresses: {iface.addresses}")
    print()
    print("Start a capture with:")
    print("  python -m stunscope capture -i <name-or-index> --duration 30")
    print()
    print("Note: opening most interfaces on Windows requires an elevated")
    print("(Administrator) terminal, and Npcap must be installed.")
    return EXIT_OK


def _cmd_capture(args) -> int:
    packet_filter = _build_filter_from_args(args)
    try:
        iface = _resolve_interface(args.interface)
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    ports: Optional[tuple[int, ...]] = None
    if args.ports is not None:
        try:
            ports = tuple(
                int(p, 0) for p in str(args.ports).replace(" ", "").split(",") if p
            )
        except ValueError:
            print(
                "error: --ports expects a comma-separated list like '3478,19302'",
                file=sys.stderr,
            )
            return EXIT_USAGE
        bad = [p for p in ports if not 1 <= p <= 65535]
        if bad:
            print(f"error: invalid port(s): {bad}", file=sys.stderr)
            return EXIT_USAGE

    engine = CaptureEngine(iface.name, interface_label=iface.description, ports=ports)
    records: list[PacketRecord] = []
    shown_records: list[PacketRecord] = []

    def on_packet(record: PacketRecord) -> None:
        records.append(record)
        if packet_filter.matches(record):
            shown_records.append(record)
            print(_format_record_line(record, args.verbose), flush=True)

    print(_BANNER)
    print(f"Interface:   {iface.description}")
    print(f"Filters:     {packet_filter.describe()}")
    if ports:
        print(f"Port filter: {', '.join(str(p) for p in ports)} (convenience pre-filter)")
    print("Notice:      capture may require Administrator privileges; only inspect")
    print("             traffic you are authorized to analyze.")
    print("Press Ctrl+C to stop and finalize any CSV export.")
    print()

    stats = None
    try:
        engine.start(on_packet, duration=args.duration, max_packets=args.max_packets)
    except KeyboardInterrupt:
        print()
        print("Stopping capture…")
        engine.stop()
    except CaptureUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        stats = engine.stats

    _print_summary(shown_records, stats)
    return _export_records(shown_records, args.csv, args.redact, packet_filter)


def _cmd_parse_file(args) -> int:
    """Parse hex-encoded STUN messages from a text file (no capture needed).

    Line formats (one message per line)::

        # comment lines are ignored
        <hex-encoded STUN message>
        <src-ip>:<src-port>-><dst-ip>:<dst-port> <hex-encoded message>
    """
    path = Path(args.file).expanduser()
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return EXIT_USAGE
    packet_filter = _build_filter_from_args(args)

    records: list[PacketRecord] = []
    base_time = time.time()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    skipped = 0
    from stunscope.capture import build_record

    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        src_ip, src_port = "192.0.2.10", 50000
        dst_ip, dst_port = "198.51.100.20", 3478
        if " " in line:
            header, _, hex_part = line.partition(" ")
            hex_part = hex_part.strip()
            if "->" in header:
                source, _, destination = header.partition("->")
                try:
                    src_ip, src_port_text = source.rsplit(":", 1)
                    dst_ip, dst_port_text = destination.rsplit(":", 1)
                    src_port, dst_port = int(src_port_text), int(dst_port_text)
                except ValueError:
                    print(
                        f"warning: line {number}: malformed endpoint header, using defaults",
                        file=sys.stderr,
                    )
                    src_ip, src_port, dst_ip, dst_port = "192.0.2.10", 50000, "198.51.100.20", 3478
            line = hex_part
        try:
            payload = bytes.fromhex(line)
        except ValueError:
            skipped += 1
            print(f"warning: line {number}: not valid hex, skipped", file=sys.stderr)
            continue
        record = build_record(
            src_ip, src_port, dst_ip, dst_port, payload,
            interface="file", timestamp=base_time + number / 1000,
        )
        if record is None:
            skipped += 1
            continue
        records.append(record)

    shown = [r for r in records if packet_filter.matches(r)]
    for record in shown:
        print(_format_record_line(record, args.verbose))

    print()
    print(f"Parsed {len(records)} STUN message(s); {skipped} line(s) skipped.")
    if packet_filter.is_active():
        print(f"Filters: {packet_filter.describe()} — {len(shown)} matched.")
    return _export_records(shown, args.csv, args.redact, packet_filter)


def _cmd_gui(args) -> int:
    try:
        from stunscope.gui.main import run
    except ImportError as exc:
        print(
            "error: PySide6 is not installed, so the GUI cannot start "
            f"({exc}).\n"
            "       Install it with:  pip install PySide6\n"
            "       or reinstall the full package: pip install -r requirements.txt",
            file=sys.stderr,
        )
        return EXIT_USAGE
    return run()


def _cmd_info(args) -> int:
    import platform

    print(f"STUNScope {__version__}")
    print(f"Python:     {platform.python_version()} ({platform.machine()})")
    print(f"Platform:   {platform.system()} {platform.release()}")
    print(f"Scapy:      {'available' if scapy_available() else 'NOT installed'}")
    import importlib.util

    pyside = importlib.util.find_spec("PySide6")
    print(f"PySide6:    {'available' if pyside else 'NOT installed (GUI disabled)'}")
    if scapy_available():
        try:
            interfaces = list_interfaces()
            print(f"Interfaces: {len(interfaces)} capture device(s) found")
        except CaptureUnavailableError as exc:
            print(f"Interfaces: unavailable — {exc}")
    else:
        print("Interfaces: unavailable — Scapy missing")
    print(f"Config dir: {config_dir()}")
    print(f"Settings:   {settings_path()}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _add_filter_options(subparser: argparse.ArgumentParser) -> None:
    group = subparser.add_argument_group("filters")
    group.add_argument(
        "--message-type",
        metavar="TYPE",
        default="",
        help="STUN message type filter: binding-request, binding-success, "
        "binding-error, binding-indication, binding, request, indication, "
        "success, error, or a hex type such as 0x0111",
    )
    group.add_argument("--src", metavar="IP", default="", help="source IP (exact, CIDR, or prefix*)")
    group.add_argument("--dst", metavar="IP", default="", help="destination IP (exact, CIDR, or prefix*)")
    group.add_argument(
        "--transaction-id",
        metavar="HEX",
        default="",
        help="transaction ID (hex; prefixes match)",
    )
    group.add_argument(
        "--validity",
        choices=("any", "valid", "malformed"),
        default="any",
        help="keep valid or malformed messages (default: any)",
    )
    group.add_argument("--search", metavar="TEXT", default="", help="free-text match across all fields")
    group.add_argument(
        "--csv",
        metavar="PATH",
        default="",
        help="export the filtered results to a UTF-8 CSV file",
    )
    group.add_argument(
        "--redact",
        action="store_true",
        help="mask IP addresses in the exported CSV (privacy mode)",
    )


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    """Global options accepted before *and* after the subcommand.

    ``default=argparse.SUPPRESS`` keeps a subparser from clobbering a
    value parsed by the top-level parser when the flag is only given in
    one of the two positions.
    """
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="print fully decoded message details for every packet",
    )
    parser.add_argument(
        "--no-log-file",
        action="store_true",
        default=argparse.SUPPRESS,
        help="disable the rotating diagnostic log file",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m stunscope",
        description=_BANNER
        + "\n\nAnalyze STUN (RFC 8489) traffic on networks you own or are "
        "authorized to test. Provides live capture, protocol decoding, "
        "filters, and CSV export.",
        epilog="Live capture needs Scapy plus Npcap on Windows and usually an "
        "elevated terminal. Example: python -m stunscope capture -i 1 --duration 30 "
        "--csv out.csv",
    )
    parser.add_argument("--version", action="version", version=f"STUNScope {__version__}")
    _add_common_options(parser)
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    def make_sub(name: str, **kwargs):
        subparser = subparsers.add_parser(name, **kwargs)
        _add_common_options(subparser)
        return subparser

    make_sub(
        "list-interfaces",
        aliases=["interfaces", "li"],
        help="list available capture interfaces and exit",
        description="Enumerate capture interfaces (requires Scapy and Npcap).",
    ).set_defaults(func=_cmd_list_interfaces)

    capture_parser = make_sub(
        "capture",
        help="capture STUN traffic live on an interface",
        description="Capture and decode STUN traffic live. Ctrl+C stops the "
        "capture cleanly and finalizes any requested CSV export.",
    )
    capture_parser.add_argument(
        "-i",
        "--interface",
        required=True,
        metavar="IFACE",
        help="interface to capture on: Scapy name, 1-based index, or a unique "
        "substring of its description",
    )
    capture_parser.add_argument(
        "--duration",
        type=float,
        default=None,
        metavar="SEC",
        help="stop after this many seconds (default: run until Ctrl+C)",
    )
    capture_parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        metavar="N",
        help="stop after this many STUN messages have been parsed",
    )
    capture_parser.add_argument(
        "--ports",
        metavar="LIST",
        default=None,
        help="optional convenience port pre-filter, e.g. '3478,19302' "
        f"(common STUN ports: {', '.join(str(p) for p in COMMON_STUN_PORTS)})",
    )
    _add_filter_options(capture_parser)
    capture_parser.set_defaults(func=_cmd_capture)

    parse_parser = make_sub(
        "parse-file",
        help="parse hex-encoded STUN messages from a text file",
        description="Offline parser: reads one hex-encoded STUN message per "
        "line (no Npcap or privileges needed). Lines may start with "
        "'src-ip:port->dst-ip:port ' to set packet metadata.",
    )
    parse_parser.add_argument("file", metavar="FILE", help="input text file")
    _add_filter_options(parse_parser)
    parse_parser.set_defaults(func=_cmd_parse_file)

    gui_parser = make_sub(
        "gui",
        help="launch the PySide6 desktop interface",
        description="Launch the desktop GUI (requires PySide6).",
    )
    gui_parser.set_defaults(func=_cmd_gui)

    info_parser = make_sub(
        "info",
        help="show version and environment details",
        description="Report versions, capture availability, and config paths.",
    )
    info_parser.set_defaults(func=_cmd_info)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    setup_logging(verbose="--verbose" in argv, log_to_file="--no-log-file" not in argv)

    parser = build_parser()
    args = parser.parse_args(argv)
    # Global flags are accepted before or after the subcommand; SUPPRESS
    # defaults mean the attribute may be missing entirely.
    args.verbose = getattr(args, "verbose", False)
    args.no_log_file = getattr(args, "no_log_file", False)

    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    try:
        return args.func(args)
    except FilterError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
