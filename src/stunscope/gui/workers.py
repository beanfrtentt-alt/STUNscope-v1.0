"""Capture worker bridging the shared CaptureEngine to the GUI thread.

The worker runs :meth:`stunscope.capture.CaptureEngine.start` on a
QThread. Parsed packets are batched (up to 64 records or 150 ms,
whichever comes first) and handed to the GUI via a queued signal, so the
capture thread never blocks on UI work and the UI never touches sockets.

Memory safety: the worker keeps at most ``PENDING_CAP`` unflushed
records; beyond that the oldest are dropped (and counted) rather than
growing without bound. The table model applies its own display cap.
"""

from __future__ import annotations

import time
from typing import Optional

from PySide6.QtCore import QObject, Signal

from stunscope.capture import CaptureEngine, CaptureError
from stunscope.models import PacketRecord

BATCH_SIZE = 64
FLUSH_INTERVAL = 0.15
PENDING_CAP = 4000


class CaptureWorker(QObject):
    """Owns one CaptureEngine; emit-driven, GUI-safe.

    Intended usage (MainWindow)::

        thread = QThread()
        worker = CaptureWorker(interface_name, interface_label, ports)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.batch_ready.connect(model.add_packets)   # queued, thread-safe
        ...
    """

    started_capture = Signal(str)  # interface label
    stopped_capture = Signal(dict)  # final engine stats
    capture_failed = Signal(str)
    batch_ready = Signal(list)  # list[PacketRecord]
    status_updated = Signal(int)  # records emitted so far

    def __init__(
        self,
        interface_name: str,
        interface_label: str = "",
        ports: Optional[tuple[int, ...]] = None,
        duration: Optional[float] = None,
        max_packets: Optional[int] = None,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._engine = CaptureEngine(
            interface=interface_name,
            interface_label=interface_label or interface_name,
            ports=ports,
        )
        self._duration = duration
        self._max_packets = max_packets
        self._buffer: list[PacketRecord] = []
        self._last_flush = time.monotonic()
        self._emitted = 0
        self._dropped = 0

    # -- control -------------------------------------------------------------
    def request_stop(self) -> None:
        """Thread-safe; the engine loop polls this at 10 Hz."""
        self._engine.stop()

    @property
    def interface_label(self) -> str:
        return self._engine.interface_label

    # -- main loop ------------------------------------------------------------
    def run(self) -> None:
        self._last_flush = time.monotonic()
        self.started_capture.emit(self._engine.interface_label)
        try:
            self._engine.start(
                self._on_packet,
                duration=self._duration,
                max_packets=self._max_packets,
            )
        except CaptureError as exc:
            self._flush()
            self.capture_failed.emit(str(exc))
            return
        except Exception as exc:  # engine internals; keep the GUI alive
            self._flush()
            self.capture_failed.emit(f"unexpected capture failure: {exc}")
            return
        self._flush()
        stats = dict(
            packets_seen=self._engine.stats.packets_seen,
            records_emitted=self._engine.stats.records_emitted,
            errors=self._engine.stats.errors,
            duration=self._engine.stats.duration_seconds,
            dropped=self._dropped,
        )
        self.stopped_capture.emit(stats)

    # -- internals ----------------------------------------------------------
    def _on_packet(self, record: PacketRecord) -> None:
        self._buffer.append(record)
        self._emitted += 1
        now = time.monotonic()
        if len(self._buffer) >= BATCH_SIZE or now - self._last_flush >= FLUSH_INTERVAL:
            self._flush()
        elif self._emitted % 25 == 0:
            self.status_updated.emit(self._emitted)

    def _flush(self) -> None:
        if not self._buffer:
            return
        overflow = len(self._buffer) - PENDING_CAP
        if overflow > 0:
            self._dropped += overflow
            del self._buffer[:overflow]
        batch = self._buffer
        self._buffer = []
        self._last_flush = time.monotonic()
        self.batch_ready.emit(batch)
        self.status_updated.emit(self._emitted)
