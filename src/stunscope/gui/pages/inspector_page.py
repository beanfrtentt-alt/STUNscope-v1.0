"""Packet Inspector: full metadata, decoded header, attributes, raw bytes."""

from __future__ import annotations

import datetime as _dt
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFormLayout,
    QFrame,
    QHeaderView,
    QLabel,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from stunscope.gui.models import FilterProxyModel, PacketTableModel, record_for_index
from stunscope.gui.widgets import Card, EmptyState, SectionLabel
from stunscope.models import NOT_AVAILABLE, PacketRecord
from stunscope.parser import (
    ATTRIBUTE_OK,
    format_hex_dump,
)

ATTRIBUTE_COLUMNS = ["Attribute", "Type", "Length", "Value", "Status", "Note"]


class InspectorPage(QWidget):
    """Left: packet list (shared selection). Right: decoded details."""

    def __init__(
        self,
        model: PacketTableModel,
        proxy: FilterProxyModel,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._model = model
        self._proxy = proxy
        self._record: Optional[PacketRecord] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        title = QLabel("Packet Inspector")
        title.setObjectName("HeaderTitle")
        layout.addWidget(title)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ---- left: packet list (selection model shared with Live Capture) --
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.table = self._build_packet_table()
        left_layout.addWidget(self.table)
        splitter.addWidget(left)

        # ---- right: details --------------------------------------------------
        details_scroll = QScrollArea()
        details_scroll.setWidgetResizable(True)
        details_scroll.setFrameShape(QFrame.Shape.NoFrame)
        details_holder = QWidget()
        details_layout = QVBoxLayout(details_holder)
        details_layout.setContentsMargins(12, 0, 0, 0)
        details_layout.setSpacing(12)

        self.details_empty = EmptyState(
            "Select a packet",
            "Click a packet in the list (or double-click one in Live Capture) to "
            "inspect its decoded STUN header, attributes, and raw bytes.",
        )
        details_layout.addWidget(self.details_empty)

        self.details_widget = QWidget()
        self.details_widget.setVisible(False)
        details_body = QVBoxLayout(self.details_widget)
        details_body.setContentsMargins(0, 0, 0, 0)
        details_body.setSpacing(12)

        # warning banner
        self.banner = QLabel("")
        self.banner.setObjectName("WarningBanner")
        self.banner.setWordWrap(True)
        self.banner.setVisible(False)
        details_body.addWidget(self.banner)

        # metadata card
        meta_card = Card()
        meta_layout = QFormLayout(meta_card)
        meta_layout.setContentsMargins(16, 12, 16, 12)
        meta_layout.setSpacing(6)
        meta_layout.addRow(SectionLabel("PACKET METADATA"), QLabel(""))
        self.meta_rows: dict[str, QLabel] = {}
        for field in (
            "timestamp",
            "interface",
            "endpoints",
            "protocol",
            "parse_status",
            "note",
        ):
            value = QLabel("—")
            value.setWordWrap(True)
            self.meta_rows[field] = value
            meta_layout.addRow(self._pretty(field), value)
        details_body.addWidget(meta_card)

        # header card
        header_card = Card()
        header_layout = QFormLayout(header_card)
        header_layout.setContentsMargins(16, 12, 16, 12)
        header_layout.setSpacing(6)
        header_layout.addRow(SectionLabel("STUN HEADER"), QLabel(""))
        self.header_rows: dict[str, QLabel] = {}
        for field in (
            "message_type",
            "message_class",
            "method",
            "message_length",
            "magic_cookie",
            "transaction_id",
        ):
            value = QLabel("—")
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.header_rows[field] = value
            header_layout.addRow(self._pretty(field), value)
        details_body.addWidget(header_card)

        # mapped-address card
        mapped_card = Card()
        mapped_layout = QFormLayout(mapped_card)
        mapped_layout.setContentsMargins(16, 12, 16, 12)
        mapped_layout.setSpacing(6)
        mapped_layout.addRow(SectionLabel("OBSERVED ADDRESSES"), QLabel(""))
        self.mapped_rows: dict[str, QLabel] = {}
        for field in ("mapped_address", "xor_mapped_address"):
            value = QLabel(NOT_AVAILABLE)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.mapped_rows[field] = value
            mapped_layout.addRow(self._pretty(field), value)
        self.address_note = QLabel(
            "The XOR-MAPPED-ADDRESS is the NAT binding the STUN server observed for "
            "the request sender — not a remote participant address by itself."
        )
        self.address_note.setObjectName("MutedText")
        self.address_note.setWordWrap(True)
        mapped_layout.addRow(self.address_note)
        details_body.addWidget(mapped_card)

        # attributes table
        attributes_card = Card()
        attributes_card_layout = QVBoxLayout(attributes_card)
        attributes_card_layout.setContentsMargins(0, 0, 0, 0)
        attributes_card_layout.setSpacing(0)
        attributes_header = QLabel("  ATTRIBUTES")
        attributes_header.setObjectName("SectionLabel")
        attributes_card_layout.addWidget(attributes_header)
        self.attributes_table = QTableWidget(0, len(ATTRIBUTE_COLUMNS))
        self.attributes_table.setHorizontalHeaderLabels(ATTRIBUTE_COLUMNS)
        self.attributes_table.verticalHeader().setVisible(False)
        self.attributes_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.attributes_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.attributes_table.setAlternatingRowColors(True)
        attributes_header_view = self.attributes_table.horizontalHeader()
        attributes_header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        attributes_header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        attributes_header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        attributes_header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        attributes_header_view.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        attributes_header_view.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        attributes_card_layout.addWidget(self.attributes_table)
        details_body.addWidget(attributes_card, stretch=1)

        # raw bytes
        raw_card = Card()
        raw_layout = QVBoxLayout(raw_card)
        raw_layout.setContentsMargins(16, 12, 16, 12)
        raw_layout.addWidget(SectionLabel("RAW PAYLOAD"))
        self.raw_dump = QTextEdit()
        self.raw_dump.setObjectName("RawDump")
        self.raw_dump.setReadOnly(True)
        raw_layout.addWidget(self.raw_dump)
        details_body.addWidget(raw_card)

        details_layout.addWidget(self.details_widget)
        details_scroll.setWidget(details_holder)
        splitter.addWidget(details_scroll)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)

        layout.addWidget(splitter, stretch=1)

    # -- public ---------------------------------------------------------------
    def attach_selection_model(self, table) -> None:
        """Share the Live Capture table's selection model with our list."""
        self.table.setModel(table.model())
        self.table.setSelectionModel(table.selectionModel())
        self.table.selectionModel().currentRowChanged.connect(self._on_current_row)

    def set_record(self, record: Optional[PacketRecord]) -> None:
        """Populate the detail panes (also callable programmatically)."""
        self._record = record
        if record is None:
            self.details_widget.setVisible(False)
            self.details_empty.setVisible(True)
            return
        self.details_empty.setVisible(False)
        self.details_widget.setVisible(True)

        message = record.message

        # banner ------------------------------------------------------------
        if record.parse_status == "malformed":
            self.banner.setText(f"⚠ Malformed message — {record.note or 'protocol violation'}")
            self.banner.setVisible(True)
        elif record.note:
            self.banner.setText(f"⚠ {record.note}")
            self.banner.setVisible(True)
        else:
            self.banner.setVisible(False)

        # metadata ------------------------------------------------------------
        stamp = _dt.datetime.fromtimestamp(record.timestamp)
        self.meta_rows["timestamp"].setText(stamp.strftime("%Y-%m-%d %H:%M:%S.") + f"{int(record.timestamp % 1 * 1000):03d}")
        self.meta_rows["interface"].setText(record.interface or NOT_AVAILABLE)
        self.meta_rows["endpoints"].setText(
            f"{record.src_ip}:{record.src_port}  →  {record.dst_ip}:{record.dst_port}"
        )
        self.meta_rows["protocol"].setText(record.protocol)
        self.meta_rows["parse_status"].setText(
            "Valid" if record.parse_status == "valid" else "Malformed"
        )
        self.meta_rows["note"].setText(record.note or "—")

        # header ----------------------------------------------------------------
        if message is not None:
            self.header_rows["message_type"].setText(
                f"{message.message_type_hex}"
                + (f" — {message.method_name} {message.message_class}" if message.valid else "")
            )
            self.header_rows["message_class"].setText(
                message.message_class if message.valid else NOT_AVAILABLE
            )
            self.header_rows["method"].setText(
                f"{message.method_name} (0x{message.method:03X})" if message.valid else NOT_AVAILABLE
            )
            self.header_rows["message_length"].setText(
                f"{message.message_length} bytes" if message.valid else NOT_AVAILABLE
            )
            self.header_rows["magic_cookie"].setText("0x2112A442" if message.valid else NOT_AVAILABLE)
            self.header_rows["transaction_id"].setText(message.transaction_id or NOT_AVAILABLE)
        else:
            for label in self.header_rows.values():
                label.setText(NOT_AVAILABLE)

        # addresses --------------------------------------------------------------
        mapped = message.mapped_address() if message is not None else None
        xor_attr = message.attribute(0x0020) if message is not None else None
        plain_attr = message.attribute(0x0001) if message is not None else None
        self.mapped_rows["mapped_address"].setText(
            f"{plain_attr.decoded['address']}:{plain_attr.decoded['port']} "
            f"({plain_attr.decoded['family']})"
            if plain_attr is not None and plain_attr.decoded and "address" in plain_attr.decoded
            else NOT_AVAILABLE
        )
        self.mapped_rows["xor_mapped_address"].setText(
            f"{xor_attr.decoded['address']}:{xor_attr.decoded['port']} "
            f"({xor_attr.decoded['family']})"
            if xor_attr is not None and xor_attr.decoded and "address" in xor_attr.decoded
            else NOT_AVAILABLE
        )
        if mapped is None:
            self.address_note.setText(
                "This message carries no mapped address (typical for requests)."
            )
        else:
            self.address_note.setText(
                "Server-observed mapping of the request sender (usually the local "
                "NAT binding). Not a remote participant address by itself."
            )

        # attributes ---------------------------------------------------------------
        self.attributes_table.setRowCount(0)
        if message is not None:
            for attr in message.attributes:
                row = self.attributes_table.rowCount()
                self.attributes_table.insertRow(row)
                status_icon = "✓" if attr.status == ATTRIBUTE_OK else "⚠"
                values = [
                    attr.type_name,
                    f"0x{attr.type:04X}",
                    str(attr.length),
                    self._attribute_value(attr),
                    f"{status_icon} {attr.status}",
                    attr.note,
                ]
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if column in (4, 5):
                        item.setToolTip(value)
                    if attr.status != ATTRIBUTE_OK and column == 4:
                        from PySide6.QtGui import QColor

                        item.setForeground(QColor("#e5b567"))
                    self.attributes_table.setItem(row, column, item)

        # raw ------------------------------------------------------------------------
        if record.payload:
            self.raw_dump.setPlainText(format_hex_dump(record.payload))
        else:
            self.raw_dump.setPlainText("(payload not retained)")

    # -- internals ---------------------------------------------------------------
    def _build_packet_table(self):
        from PySide6.QtWidgets import QTableView

        table = QTableView()
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.verticalHeader().setVisible(False)
        return table

    def _on_current_row(self, current, _previous) -> None:
        record = record_for_index(self._proxy, current) if current.isValid() else None
        self.set_record(record)

    @staticmethod
    def _pretty(field: str) -> str:
        names = {
            "timestamp": "Timestamp",
            "interface": "Interface",
            "endpoints": "Source → Destination",
            "protocol": "Protocol",
            "parse_status": "Parse status",
            "note": "Diagnostic",
            "message_type": "Message type",
            "message_class": "Class",
            "method": "Method",
            "message_length": "Message length",
            "magic_cookie": "Magic cookie",
            "transaction_id": "Transaction ID",
            "mapped_address": "MAPPED-ADDRESS",
            "xor_mapped_address": "XOR-MAPPED-ADDRESS",
        }
        return names.get(field, field)

    @staticmethod
    def _attribute_value(attr) -> str:
        if attr.decoded is None:
            raw = attr.raw[:16].hex()
            suffix = "…" if len(attr.raw) > 16 else ""
            return f"raw: {raw}{suffix}"
        if "address" in attr.decoded:
            return f"{attr.decoded['address']}:{attr.decoded['port']} ({attr.decoded['family']})"
        if "code" in attr.decoded:
            return f"{attr.decoded['code']} {attr.decoded.get('reason', '')}".strip()
        if "value" in attr.decoded:
            text = str(attr.decoded["value"])
            return text if len(text) <= 120 else text[:117] + "…"
        if "value_hex" in attr.decoded:
            return attr.decoded["value_hex"][:64]
        return ""
