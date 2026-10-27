"""Qt data models for the packet table.

The model wraps the bounded in-memory packet list and keeps live
dashboard counters. All filtering happens in :class:`FilterProxyModel`,
which delegates to the shared :class:`~stunscope.filters.PacketFilter` —
the same predicate the CLI uses.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
    Signal,
)

from stunscope.filters import PacketFilter
from stunscope.models import PacketRecord, StunMessage
from stunscope.parser import short_transaction_id

COLUMNS = ["Time", "Source", "Destination", "Type", "Transaction ID", "Attrs", "Status"]


def _time_label(timestamp: float) -> str:
    import time as _time

    return _time.strftime("%H:%M:%S", _time.localtime(timestamp)) + (
        f".{int((timestamp % 1) * 1000):03d}"
    )


def record_for_index(model, proxy_index) -> Optional[PacketRecord]:
    """Map any view index (proxy or source) back to its PacketRecord."""
    if not proxy_index.isValid():
        return None
    source = proxy_index.model()
    while isinstance(source, QSortFilterProxyModel):
        proxy_index = source.mapToSource(proxy_index)
        source = source.sourceModel()
    if isinstance(source, PacketTableModel):
        return source.record(proxy_index.row())
    return None


class PacketTableModel(QAbstractTableModel):
    """Bounded, append-only table of captured packets.

    Memory safety: the list is capped at ``max_rows``; when the cap is
    hit the oldest rows are dropped (bulk removal) so a long unattended
    capture cannot grow without bound. When paused, incoming packets
    accumulate in a bounded pending buffer and are flushed on resume —
    capture itself is unaffected.
    """

    stats_changed = Signal(dict)
    rows_changed = Signal(int)  # new total row count

    def __init__(self, max_rows: int = 5000, parent=None) -> None:
        super().__init__(parent)
        self._records: list[PacketRecord] = []
        self._pending: list[PacketRecord] = []
        self._max_rows = max(100, int(max_rows))
        self._paused = False
        self._stats = {
            "total": 0,
            "valid": 0,
            "malformed": 0,
            "binding_requests": 0,
            "binding_success": 0,
            "binding_errors": 0,
            "dropped": 0,
        }

    # -- Qt model API ------------------------------------------------------
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._records)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            record = self._records[index.row()]
            column = index.column()
            if column == 0:
                return _time_label(record.timestamp)
            if column == 1:
                return f"{record.src_ip}:{record.src_port}"
            if column == 2:
                return f"{record.dst_ip}:{record.dst_port}"
            if column == 3:
                return record.type_label()
            if column == 4:
                return short_transaction_id(record.transaction_id(), keep=6)
            if column == 5:
                message = record.message
                return str(len(message.attributes)) if message else "0"
            if column == 6:
                return "Valid" if record.parse_status == "valid" else "Malformed"
        elif role == Qt.ItemDataRole.ToolTipRole:
            record = self._records[index.row()]
            tip = f"{record.src_ip}:{record.src_port} → {record.dst_ip}:{record.dst_port}"
            transaction = record.transaction_id()
            if transaction:
                tip += f"\nTransaction ID: {transaction}"
            if record.note:
                tip += f"\n{record.note}"
            return tip
        elif role == Qt.ItemDataRole.ForegroundRole:
            record = self._records[index.row()]
            if index.column() == 6:
                from PySide6.QtGui import QBrush, QColor

                color = QColor("#57c785") if record.parse_status == "valid" else QColor("#e5697a")
                return QBrush(color)
        return None

    def headerData(self, section: int, orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if (
            orientation == Qt.Orientation.Horizontal
            and role == Qt.ItemDataRole.DisplayRole
            and 0 <= section < len(COLUMNS)
        ):
            return COLUMNS[section]
        return None

    # -- STUNScope API -----------------------------------------------------
    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def record(self, row: int) -> Optional[PacketRecord]:
        if 0 <= row < len(self._records):
            return self._records[row]
        return None

    def all_records(self) -> list[PacketRecord]:
        return list(self._records)

    def row_count(self) -> int:
        return len(self._records)

    def set_max_rows(self, max_rows: int) -> None:
        self._max_rows = max(100, int(max_rows))
        self._trim_to_cap()

    def set_paused(self, paused: bool) -> None:
        """Freeze visual updates; buffered packets flush on resume."""
        if self._paused == paused:
            return
        self._paused = paused
        if not paused and self._pending:
            self.add_packets([])

    def add_packets(self, packets: list[PacketRecord]) -> None:
        """Ingest a batch of parsed packets (called with batch signals)."""
        if self._paused:
            if packets:
                overflow = len(self._pending) + len(packets) - self._max_rows
                if overflow > 0:
                    del self._pending[:overflow]
                    self._stats["dropped"] += overflow
                self._pending.extend(packets)
                for record in packets:
                    self._count(record, +1)
                self.stats_changed.emit(dict(self._stats))
            return
        if packets:
            start = len(self._records)
            self.beginInsertRows(QModelIndex(), start, start + len(packets) - 1)
            self._records.extend(packets)
            self.endInsertRows()
            for record in packets:
                self._count(record, +1)
        if self._pending:
            # Resume path: flush everything that was buffered while paused.
            start = len(self._records)
            batch = self._pending
            self._pending = []
            self.beginInsertRows(QModelIndex(), start, start + len(batch) - 1)
            self._records.extend(batch)
            self.endInsertRows()
        self._trim_to_cap()
        self.rows_changed.emit(len(self._records))
        self.stats_changed.emit(dict(self._stats))

    def clear(self) -> None:
        self.beginResetModel()
        self._records.clear()
        self._pending.clear()
        self._stats = {key: 0 for key in self._stats}
        self.endResetModel()
        self.rows_changed.emit(0)
        self.stats_changed.emit(dict(self._stats))

    # -- internals ----------------------------------------------------------
    def _count(self, record: PacketRecord, delta: int) -> None:
        self._stats["total"] += delta
        message: Optional[StunMessage] = record.message
        if record.parse_status == "valid":
            self._stats["valid"] += delta
        else:
            self._stats["malformed"] += delta
        if message is not None and message.valid:
            if message.is_binding_request():
                self._stats["binding_requests"] += delta
            elif message.is_binding_success():
                self._stats["binding_success"] += delta
            elif message.is_binding_error():
                self._stats["binding_errors"] += delta

    def _trim_to_cap(self) -> None:
        overflow = len(self._records) - self._max_rows
        if overflow <= 0:
            return
        removed = self._records[:overflow]
        self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
        del self._records[:overflow]
        self.endRemoveRows()
        for record in removed:
            self._count(record, -1)
        self._stats["dropped"] += len(removed)


class FilterProxyModel(QSortFilterProxyModel):
    """Applies the shared PacketFilter to the packet table view."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.packet_filter = PacketFilter()
        self.setFilterKeyColumn(-1)  # unused; filterAcceptsRow is custom

    def set_packet_filter(self, packet_filter: PacketFilter) -> None:
        self.packet_filter = packet_filter
        self.invalidateFilter()

    def refresh(self) -> None:
        self.invalidateFilter()

    def filtered_records(self) -> list[PacketRecord]:
        source = self.sourceModel()
        records: list[PacketRecord] = []
        for row in range(self.rowCount()):
            index = self.index(row, 0)
            source_row = self.mapToSource(index).row()
            record = source.record(source_row) if isinstance(source, PacketTableModel) else None
            if record is not None:
                records.append(record)
        return records

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        source = self.sourceModel()
        if not isinstance(source, PacketTableModel):
            return True
        record = source.record(source_row)
        if record is None:
            return True
        return self.packet_filter.matches(record)
