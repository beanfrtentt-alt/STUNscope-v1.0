"""Live packet capture built on Scapy + Npcap, shared by CLI and GUI.

Design notes
------------
- Scapy is imported lazily inside functions. Unit tests, the CSV
  exporter, and the parser run on machines without Scapy/Npcap; the CLI
  and GUI degrade to a clear error message instead of crashing.
- STUN detection is *structural*: any UDP datagram whose payload carries
  the STUN magic cookie and framing bits is parsed by the shared parser.
  An optional list of ports ("3478, 5349, 19302, ...") can narrow the
  BPF filter as a convenience — it is never the only detection method.
- Stopping is prompt even on idle interfaces because the capture runs on
  Scapy's ``AsyncSniffer``, which closes the pcap handle from another
  thread, while the engine polls a stop event at 10 Hz.
- The engine never writes to disk and never sends traffic; it only
  reads datagrams that were already addressed to the machine or visible
  to the selected interface. Use it only on networks you own or are
  authorized to test.

Windows prerequisites: an Npcap installation with the "Install Npcap in
WinPcap API-compatible Mode" option enabled, and (for most interfaces)
capture started from an elevated shell. See
``docs/installation-windows.md``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from stunscope.logging_config import get_logger
from stunscope.models import (
    PARSE_MALFORMED,
    PARSE_OK,
    PacketRecord,
)
from stunscope.parser import maybe_stun, parse_stun_message

logger = get_logger("capture")

# How much of each payload we keep in memory for the inspector.
MAX_PAYLOAD_KEEP = 2048

# Common STUN ports. Purely optional convenience pre-filters.
COMMON_STUN_PORTS = (3478, 5349, 19302)

_POLL_INTERVAL = 0.1

try:  # pragma: no cover - environment dependent
    import scapy  # noqa: F401  (presence probe)

    _SCAPY_IMPORT_ERROR: Optional[str] = None
except Exception as exc:  # pragma: no cover
    scapy = None
    _SCAPY_IMPORT_ERROR = str(exc)


class CaptureError(RuntimeError):
    """Base class for capture failures with user-readable messages."""


class CaptureUnavailableError(CaptureError):
    """Scapy missing, Npcap missing, or no usable interface."""


class CaptureInterfaceError(CaptureError):
    """The requested interface could not be used."""


@dataclass
class InterfaceInfo:
    """A capture interface as shown in pickers and ``list-interfaces``."""

    name: str  # opaque Scapy identifier (GUID on Windows)
    description: str  # human-readable label
    addresses: str  # comma-separated configured addresses (display only)

    def label(self) -> str:
        if self.description and self.description != self.name:
            return f"{self.description} ({self.addresses})" if self.addresses else self.description
        return self.name


@dataclass
class CaptureStats:
    """Counters updated by the engine while a capture runs."""

    packets_seen: int = 0  # UDP datagrams delivered to the handler
    records_emitted: int = 0  # parsed STUN records handed to the callback
    errors: int = 0  # handler exceptions (capture keeps running)

    started_at: float = 0.0
    stopped_at: float = 0.0

    @property
    def duration_seconds(self) -> float:
        if not self.started_at:
            return 0.0
        end = self.stopped_at or time.time()
        return max(0.0, end - self.started_at)


def scapy_available() -> bool:
    return scapy is not None


def scapy_import_error() -> str:
    return _SCAPY_IMPORT_ERROR or ""


def _require_scapy() -> None:
    if scapy is None:
        raise CaptureUnavailableError(
            "Scapy is not installed. Install the dependencies with "
            "`pip install -r requirements.txt` (or `pip install scapy`) "
            "and see docs/installation-windows.md for the full setup."
        )


def list_interfaces() -> list[InterfaceInfo]:
    """Enumerate capture interfaces. Raises CaptureUnavailableError."""
    _require_scapy()
    from scapy.config import conf as scapy_conf

    interfaces: list[InterfaceInfo] = []
    try:
        for dev in scapy_conf.ifaces.values():
            name = getattr(dev, "name", "") or ""
            description = getattr(dev, "description", "") or name
            addresses_list = list(getattr(dev, "ips", []) or [])
            addresses = ", ".join(a for a in addresses_list if a)[:80]
            interfaces.append(
                InterfaceInfo(
                    name=name,
                    description=description or name,
                    addresses=addresses,
                )
            )
    except Exception as exc:
        raise CaptureUnavailableError(f"could not enumerate interfaces: {exc}") from exc

    if not interfaces:
        raise CaptureUnavailableError(
            "No capture interfaces were found. On Windows this usually means "
            "Npcap is not installed (install it with the 'WinPcap API-compatible "
            "Mode' option) or the process lacks permission to open the devices. "
            "See docs/troubleshooting.md."
        )

    interfaces.sort(key=lambda iface: (iface.description.lower(), iface.name))
    return interfaces


def build_record(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    payload: bytes,
    interface: str,
    timestamp: float,
) -> Optional[PacketRecord]:
    """Turn one UDP datagram into a PacketRecord, or None if not STUN.

    This is a pure function: unit tests exercise it directly without
    Scapy or a network. Malformed STUN still produces a record — with
    a readable diagnostic — because the parser never raises.
    """
    if not maybe_stun(payload):
        return None
    message = parse_stun_message(payload)
    status = PARSE_OK if message.valid else PARSE_MALFORMED
    notes = [message.error] + list(message.warnings)
    note = "; ".join(n for n in notes if n)
    return PacketRecord(
        timestamp=timestamp,
        interface=interface,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="UDP",
        message=message,
        parse_status=status,
        note=note,
        payload=payload[:MAX_PAYLOAD_KEEP],
    )


def build_record_from_scapy(packet, interface_label: str, ports: Optional[tuple[int, ...]] = None) -> Optional[PacketRecord]:
    """Extract addressing from a Scapy packet and delegate to build_record.

    Returns None for anything that is not UDP, or whose payload has no
    STUN structure. Never raises for packet-content reasons.
    """
    try:
        from scapy.layers.inet import IP, UDP
        from scapy.layers.inet6 import IPv6

        if not packet.haslayer(UDP):
            return None
        udp = packet.getlayer(UDP)
        src_ip = dst_ip = ""
        network_layer = packet.getlayer(IP)
        if network_layer is not None:
            src_ip = network_layer.src
            dst_ip = network_layer.dst
        else:
            network_layer6 = packet.getlayer(IPv6)
            if network_layer6 is not None:
                src_ip = network_layer6.src
                dst_ip = network_layer6.dst
            else:
                return None
        if not src_ip or not dst_ip:
            return None
        if ports:
            if udp.sport not in ports and udp.dport not in ports:
                return None
        payload = bytes(udp.payload)
        timestamp = float(packet.time) if getattr(packet, "time", None) else time.time()
        return build_record(
            src_ip=src_ip,
            src_port=int(udp.sport),
            dst_ip=dst_ip,
            dst_port=int(udp.dport),
            payload=payload,
            interface=interface_label,
            timestamp=timestamp,
        )
    except Exception:
        # Unsupported packet formats must never kill the capture thread.
        logger.debug("failed to decode packet", exc_info=True)
        return None


def _bpf_filter(ports: Optional[tuple[int, ...]]) -> str:
    if not ports:
        return "udp"
    port_list = " or ".join(f"port {p}" for p in ports)
    return f"udp and ({port_list})"


class CaptureEngine:
    """Reads datagrams from one interface and emits PacketRecords.

    Usage::

        engine = CaptureEngine(interface="\\Device\\NPF_{...}", ports=(3478,))
        engine.start(on_packet=callback, duration=30.0, max_packets=100)

    ``start()`` blocks until the duration elapses, the packet maximum is
    reached, ``stop()`` is called from another thread, or the capture
    dies with an error. Callers that need the UI to stay responsive run
    ``start()`` on a worker thread (the GUI does exactly that).
    """

    def __init__(
        self,
        interface: str,
        interface_label: str = "",
        ports: Optional[tuple[int, ...]] = None,
    ) -> None:
        self._interface = interface
        self._interface_label = interface_label or interface
        self._ports: tuple[int, ...] = tuple(sorted(set(ports))) if ports else ()
        self._sniffer = None
        self._on_packet: Optional[Callable[[PacketRecord], None]] = None
        self._max_packets: Optional[int] = None
        self._stop_event = threading.Event()
        self._finished_event = threading.Event()
        self._stats = CaptureStats()
        self._lock = threading.Lock()

    # -- public API --------------------------------------------------------
    @property
    def interface(self) -> str:
        return self._interface

    @property
    def interface_label(self) -> str:
        return self._interface_label

    @property
    def ports(self) -> tuple[int, ...]:
        return self._ports

    @property
    def stats(self) -> CaptureStats:
        return self._stats

    def is_running(self) -> bool:
        return self._sniffer is not None and not self._finished_event.is_set()

    def start(
        self,
        on_packet: Callable[[PacketRecord], None],
        duration: Optional[float] = None,
        max_packets: Optional[int] = None,
    ) -> CaptureStats:
        """Run a capture. Blocking; returns final stats."""
        self._require_capture_support()
        self._on_packet = on_packet
        self._max_packets = max_packets
        self._stop_event.clear()
        self._finished_event.clear()
        self._stats = CaptureStats()
        self._stats.started_at = time.time()

        from scapy.sendrecv import AsyncSniffer

        sniffer = AsyncSniffer(
            iface=self._interface,
            filter=_bpf_filter(self._ports),
            prn=self._handle_packet,
            store=False,
        )
        self._sniffer = sniffer
        sniffer.start()

        deadline = time.monotonic() + duration if duration and duration > 0 else None
        try:
            while True:
                time.sleep(_POLL_INTERVAL)
                if self._stop_event.is_set():
                    break
                if (
                    self._max_packets is not None
                    and self._stats.records_emitted >= self._max_packets
                ):
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    break
                if not getattr(sniffer, "running", True):
                    break
        finally:
            self._sniffer = None
            try:
                if getattr(sniffer, "running", False):
                    sniffer.stop()
            except Exception:  # pragma: no cover - scapy internals
                logger.debug("sniffer stop failed", exc_info=True)
            self._stats.stopped_at = time.time()
            self._finished_event.set()
        return self._stats

    def stop(self) -> None:
        """Request a clean stop from any thread; returns immediately."""
        self._stop_event.set()

    # -- internals ----------------------------------------------------------
    def _require_capture_support(self) -> None:
        _require_scapy()
        from scapy.config import conf as scapy_conf

        names = [getattr(dev, "name", "") for dev in scapy_conf.ifaces.values()]
        if self._interface not in names:
            raise CaptureInterfaceError(
                f"interface {self._interface!r} was not found. Run "
                "`python -m stunscope list-interfaces` to see valid choices."
            )
        # Open and immediately close a capture socket so that Npcap or
        # permission problems surface here, synchronously, with a clear
        # error instead of failing silently inside the sniffer thread.
        try:
            probe = scapy_conf.L2listen(iface=self._interface, filter="udp", promisc=1)
            probe.close()
        except TypeError:
            # Unusual socket class signature — skip the probe rather than
            # rejecting a potentially valid setup; the sniffer itself will
            # surface real failures.
            pass
        except Exception as exc:
            message = str(exc)
            raise CaptureUnavailableError(
                f"could not open the capture device {self._interface!r}: {message}. "
                "On Windows: install Npcap (WinPcap API-compatible mode), and "
                "try running the terminal as Administrator if access is denied. "
                "See docs/troubleshooting.md."
            ) from exc

    def _handle_packet(self, packet) -> None:
        with self._lock:
            self._stats.packets_seen += 1
        record = build_record_from_scapy(packet, self._interface_label, self._ports)
        if record is None:
            return
        with self._lock:
            self._stats.records_emitted += 1
        callback = self._on_packet
        if callback is not None:
            try:
                callback(record)
            except Exception:
                with self._lock:
                    self._stats.errors += 1
                logger.exception("packet callback raised; capture continues")
