"""Filters page: full control over the shared PacketFilter criteria."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from stunscope.filters import PacketFilter
from stunscope.gui.widgets import Card, SectionLabel

_VALIDITY = [
    ("Any (valid and malformed)", "any"),
    ("Valid messages only", "valid"),
    ("Malformed messages only", "malformed"),
]

_TYPES = [
    ("Any message type", ""),
    ("Binding Request (0x0001)", "binding-request"),
    ("Binding Success Response (0x0101)", "binding-success"),
    ("Binding Error Response (0x0111)", "binding-error"),
    ("Binding Indication (0x0011)", "binding-indication"),
    ("Any Binding message", "binding"),
    ("Requests (any method)", "request"),
    ("Indications (any method)", "indication"),
    ("Success responses (any method)", "success"),
    ("Error responses (any method)", "error"),
]


class FiltersPage(QWidget):
    """Edit the shared filter used by the table view and CSV exports."""

    filter_changed = Signal()
    reset_requested = Signal()

    def __init__(self, packet_filter: PacketFilter, parent=None) -> None:
        super().__init__(parent)
        self._filter = packet_filter

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        title = QLabel("Filters")
        title.setObjectName("HeaderTitle")
        layout.addWidget(title)

        description = QLabel(
            "These criteria apply live to the packet table, the dashboard counts "
            "of captured packets, and “Export filtered”. The same filter object "
            "is used by the command-line interface."
        )
        description.setObjectName("MutedText")
        description.setWordWrap(True)
        layout.addWidget(description)

        card = Card()
        form = QFormLayout(card)
        form.setContentsMargins(18, 16, 18, 16)
        form.setSpacing(10)

        self.type_combo = QComboBox()
        for label, token in _TYPES:
            self.type_combo.addItem(label, userData=token)
        form.addRow("STUN message type", self.type_combo)

        self.src_edit = QLineEdit()
        self.src_edit.setPlaceholderText("e.g. 192.0.2.10, 10.0.0.0/8, or 192.0.2.*")
        form.addRow("Source IP", self.src_edit)

        self.dst_edit = QLineEdit()
        self.dst_edit.setPlaceholderText("e.g. 198.51.100.20 or 2001:db8::/32")
        form.addRow("Destination IP", self.dst_edit)

        self.transaction_edit = QLineEdit()
        self.transaction_edit.setPlaceholderText("hex; a unique prefix is enough")
        form.addRow("Transaction ID", self.transaction_edit)

        self.validity_combo = QComboBox()
        for label, token in _VALIDITY:
            self.validity_combo.addItem(label, userData=token)
        form.addRow("Message validity", self.validity_combo)

        layout.addWidget(card)

        buttons = QHBoxLayout()
        buttons.setSpacing(10)
        self.apply_button = QPushButton("Apply filters")
        self.apply_button.setObjectName("Primary")
        self.reset_button = QPushButton("Reset all filters")
        buttons.addWidget(self.apply_button)
        buttons.addWidget(self.reset_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.active_label = QLabel("")
        self.active_label.setObjectName("MutedText")
        self.active_label.setWordWrap(True)
        layout.addWidget(self.active_label)
        layout.addStretch(1)

        # wiring
        self.apply_button.clicked.connect(self.apply)
        self.reset_button.clicked.connect(self.reset)
        self.sync_widgets()

    # -- public -----------------------------------------------------------
    def sync_widgets(self) -> None:
        """Mirror the shared filter into the widgets (after reset etc.)."""
        self.src_edit.setText(self._filter.src_ip)
        self.dst_edit.setText(self._filter.dst_ip)
        self.transaction_edit.setText(self._filter.transaction_id)

        self.type_combo.blockSignals(True)
        for index in range(self.type_combo.count()):
            if self.type_combo.itemData(index) == self._filter.message_type:
                self.type_combo.setCurrentIndex(index)
                break
        else:
            self.type_combo.setCurrentIndex(0)
        self.type_combo.blockSignals(False)

        self.validity_combo.blockSignals(True)
        for index in range(self.validity_combo.count()):
            if self.validity_combo.itemData(index) == self._filter.validity:
                self.validity_combo.setCurrentIndex(index)
                break
        self.validity_combo.blockSignals(False)
        self._update_active_label()

    def apply(self) -> None:
        """Push widget values into the shared filter and notify."""
        self._filter.message_type = self.type_combo.currentData() or ""
        self._filter.src_ip = self.src_edit.text().strip()
        self._filter.dst_ip = self.dst_edit.text().strip()
        self._filter.transaction_id = self.transaction_edit.text().strip()
        self._filter.validity = self.validity_combo.currentData() or "any"
        self._update_active_label()
        self.filter_changed.emit()

    def reset(self) -> None:
        self._filter.message_type = ""
        self._filter.src_ip = ""
        self._filter.dst_ip = ""
        self._filter.transaction_id = ""
        self._filter.validity = "any"
        self._filter.search = ""
        self.sync_widgets()
        self.reset_requested.emit()
        self.filter_changed.emit()

    # -- internals -----------------------------------------------------------
    def _update_active_label(self) -> None:
        self.active_label.setText(f"Active: {self._filter.describe()}")
