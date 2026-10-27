"""Live Capture page: controls, packet table, quick filters."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDoubleSpinBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from stunscope.filters import PacketFilter
from stunscope.gui.models import FilterProxyModel, PacketTableModel, record_for_index
from stunscope.gui.widgets import Card, EmptyState

_TYPE_FILTERS = [
    ("All message types", ("message_type", "")),
    ("Binding Requests", ("message_type", "binding-request")),
    ("Binding Success Responses", ("message_type", "binding-success")),
    ("Binding Error Responses", ("message_type", "binding-error")),
    ("Binding Indications", ("message_type", "binding-indication")),
    ("Any Binding message", ("message_type", "binding")),
    ("Requests (any method)", ("message_type", "request")),
    ("Success (any method)", ("message_type", "success")),
    ("Errors (any method)", ("message_type", "error")),
    ("Valid messages only", ("validity", "valid")),
    ("Malformed messages only", ("validity", "malformed")),
]


class CapturePage(QWidget):
    """Live capture controls plus the (filtered) packet table."""

    start_requested = Signal(dict)
    stop_requested = Signal()
    filter_changed = Signal()
    record_activated = Signal(object)  # PacketRecord | None

    def __init__(
        self,
        model: PacketTableModel,
        proxy: FilterProxyModel,
        packet_filter: PacketFilter,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._model = model
        self._proxy = proxy
        self._filter = packet_filter
        self._interfaces: list[tuple[str, str]] = []  # (name, description)
        self._capture_running = False
        self._display_paused = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        title = QLabel("Live Capture")
        title.setObjectName("HeaderTitle")
        layout.addWidget(title)

        # --- controls card -------------------------------------------------
        controls_card = Card()
        controls = QHBoxLayout(controls_card)
        controls.setContentsMargins(16, 14, 16, 14)
        controls.setSpacing(10)

        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(240)
        self.interface_combo.setToolTip(
            "Capture device. Populated from Npcap; run the app as Administrator "
            "if the list is empty or devices fail to open."
        )
        self.duration_spin = QDoubleSpinBox()
        self.duration_spin.setRange(0, 86400)
        self.duration_spin.setDecimals(0)
        self.duration_spin.setSpecialValueText("until stopped")
        self.duration_spin.setToolTip(
            "Automatically stop the capture after this many seconds (0 = until stopped)."
        )
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(0, 1_000_000)
        self.limit_spin.setSpecialValueText("no limit")
        self.limit_spin.setToolTip(
            "Automatically stop after this many STUN messages (0 = no limit)."
        )
        self.ports_edit = QLineEdit()
        self.ports_edit.setPlaceholderText("e.g. 3478,19302 (optional)")
        self.ports_edit.setToolTip(
            "Optional convenience BPF port pre-filter. STUN is always detected by "
            "message structure, never by port alone."
        )

        self.start_button = self._make_button("Start capture", "Primary")
        self.stop_button = self._make_button("Stop", "Danger")
        self.pause_button = self._make_button("Pause display", "")
        self.clear_button = self._make_button("Clear table", "")

        controls.addWidget(QLabel("Interface"))
        controls.addWidget(self.interface_combo, stretch=1)
        controls.addWidget(QLabel("Duration (s)"))
        controls.addWidget(self.duration_spin)
        controls.addWidget(QLabel("Packet limit"))
        controls.addWidget(self.limit_spin)
        controls.addWidget(QLabel("Ports"))
        controls.addWidget(self.ports_edit)
        controls.addSpacing(8)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        controls.addWidget(self.pause_button)
        controls.addWidget(self.clear_button)
        layout.addWidget(controls_card)

        # --- quick filters ---------------------------------------------------
        quick = QHBoxLayout()
        quick.setSpacing(10)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search packets (IP, type, transaction ID, attributes…)")
        self.search_edit.setClearButtonEnabled(True)
        self.type_combo = QComboBox()
        for label, _ in _TYPE_FILTERS:
            self.type_combo.addItem(label)
        self.count_label = QLabel("0 packets")
        self.count_label.setObjectName("MutedText")
        self.pause_indicator = QLabel("Display paused — capture continues")
        self.pause_indicator.setObjectName("MutedText")
        self.pause_indicator.setStyleSheet("color: #e5b567;")
        self.pause_indicator.setVisible(False)

        quick.addWidget(self.search_edit, stretch=1)
        quick.addWidget(self.type_combo)
        quick.addSpacing(12)
        quick.addWidget(self.pause_indicator)
        quick.addWidget(self.count_label)
        layout.addLayout(quick)

        # --- table / empty state ----------------------------------------------
        self.stack = QStackedWidget()
        self.empty_state = EmptyState(
            "Waiting for STUN traffic",
            "Select an interface and press Start capture. STUN messages are "
            "detected by structure, not by port number.",
        )
        self.table = QTableView()
        self.table.setModel(self._proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(False)
        self.stack.addWidget(self.empty_state)
        self.stack.addWidget(self.table)
        layout.addWidget(self.stack, stretch=1)

        self.error_label = QLabel("")
        self.error_label.setObjectName("ErrorText")
        self.error_label.setWordWrap(True)
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)

        # --- wiring ------------------------------------------------------------
        self.start_button.clicked.connect(self._emit_start)
        self.stop_button.clicked.connect(self.stop_requested.emit)
        self.pause_button.clicked.connect(self._toggle_pause)
        self.clear_button.clicked.connect(self._confirm_clear)
        self.search_edit.textChanged.connect(self._apply_search)
        self.type_combo.currentIndexChanged.connect(self._apply_type_combo)
        self.table.doubleClicked.connect(self._emit_activated)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self._model.rows_changed.connect(self._on_rows_changed)
        self._proxy.rowsInserted.connect(lambda *_: self._maybe_autoscroll())
        self._proxy.rowsRemoved.connect(lambda *_: self._maybe_autoscroll())

        self.set_capture_state(False)
        self._sync_filter_widgets()

    # -- public API (MainWindow) ----------------------------------------------
    def set_interfaces(self, interfaces: list[tuple[str, str]], error: str = "") -> None:
        """Populate the interface combo; ``interfaces`` is (name, description)."""
        self._interfaces = list(interfaces)
        self.interface_combo.blockSignals(True)
        self.interface_combo.clear()
        for name, description in self._interfaces:
            self.interface_combo.addItem(description, userData=name)
        self.interface_combo.blockSignals(False)
        if error:
            self.error_label.setText(error)
            self.error_label.setVisible(True)
        else:
            self.error_label.setVisible(False)

    def select_interface(self, name: str) -> bool:
        for index in range(self.interface_combo.count()):
            if self.interface_combo.itemData(index) == name:
                self.interface_combo.setCurrentIndex(index)
                return True
        return False

    def set_capture_state(self, running: bool) -> None:
        self._capture_running = running
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.interface_combo.setEnabled(not running)
        self.duration_spin.setEnabled(not running)
        self.limit_spin.setEnabled(not running)
        self.ports_edit.setEnabled(not running)
        if not running and self._display_paused:
            self._set_paused(False)

    def current_interface(self) -> tuple[str, str]:
        index = self.interface_combo.currentIndex()
        if index < 0 or index >= len(self._interfaces):
            return "", ""
        return self._interfaces[index]

    def sync_from_filter(self) -> None:
        """Called by MainWindow after a reset; refreshes quick-filter widgets."""
        self._sync_filter_widgets()

    # -- internals -------------------------------------------------------------
    def _make_button(self, text: str, object_name: str) -> QPushButton:
        """Small helper to keep button styling declarative."""
        button = QPushButton(text)
        if object_name:
            button.setObjectName(object_name)
        return button

    def _emit_start(self) -> None:
        name, _description = self.current_interface()
        if not name:
            QMessageBox.warning(
                self,
                "No interface selected",
                "Choose a capture interface first. If the list is empty, Npcap may "
                "be missing — see the Troubleshooting page in the documentation.",
            )
            return
        duration = self.duration_spin.value()
        limit = self.limit_spin.value()
        ports: tuple[int, ...] = ()
        text = self.ports_edit.text().strip()
        if text:
            try:
                ports = tuple(int(p) for p in text.replace(" ", "").split(",") if p)
                bad = [p for p in ports if not 1 <= p <= 65535]
                if bad:
                    raise ValueError(str(bad))
            except ValueError:
                QMessageBox.warning(
                    self,
                    "Invalid ports",
                    "Ports must be a comma-separated list of numbers 1-65535, "
                    "for example: 3478, 19302.",
                )
                return
        self.start_requested.emit(
            {
                "interface_name": name,
                "ports": ports,
                "duration": duration if duration > 0 else None,
                "max_packets": limit if limit > 0 else None,
            }
        )

    def _toggle_pause(self) -> None:
        self._set_paused(not self._display_paused)

    def _set_paused(self, paused: bool) -> None:
        self._display_paused = paused
        self._model.set_paused(paused)
        self.pause_button.setText("Resume display" if paused else "Pause display")
        self.pause_indicator.setVisible(paused)
        if not paused:
            self._maybe_autoscroll()

    def _confirm_clear(self) -> None:
        answer = QMessageBox.question(
            self,
            "Clear captured packets?",
            "This removes all packets from the table and dashboard. It does not "
            "stop an active capture. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._model.clear()

    def _apply_search(self, text: str) -> None:
        self._filter.search = text
        self._proxy.refresh()
        self.filter_changed.emit()

    def _apply_type_combo(self, index: int) -> None:
        if 0 <= index < len(_TYPE_FILTERS):
            kind, value = _TYPE_FILTERS[index][1]
            if kind == "message_type":
                self._filter.message_type = value
                self._filter.validity = "any"
            else:
                self._filter.validity = value
                self._filter.message_type = ""
        self._proxy.refresh()
        self.filter_changed.emit()

    def _sync_filter_widgets(self) -> None:
        self.search_edit.blockSignals(True)
        self.search_edit.setText(self._filter.search)
        self.search_edit.blockSignals(False)
        self.type_combo.blockSignals(True)
        index = 0
        for position, (label, (kind, value)) in enumerate(_TYPE_FILTERS):
            if kind == "message_type" and self._filter.message_type == value:
                index = position
                break
            if kind == "validity" and self._filter.validity == value and not self._filter.message_type:
                index = position
                break
        else:
            index = 0
        self.type_combo.setCurrentIndex(index)
        self.type_combo.blockSignals(False)

    def _on_rows_changed(self, total: int) -> None:
        shown = self._proxy.rowCount()
        if shown != total:
            self.count_label.setText(f"{shown} shown · {total} captured")
        else:
            self.count_label.setText(f"{total} packets" if total != 1 else "1 packet")
        self.stack.setCurrentIndex(0 if total == 0 else 1)
        self._maybe_autoscroll()

    def _maybe_autoscroll(self) -> None:
        if self._display_paused:
            return
        bottom = self._model.index(self._model.rowCount() - 1, 0)
        if bottom.isValid():
            proxy_index = self._proxy.mapFromSource(bottom)
            if proxy_index.isValid():
                self.table.scrollTo(proxy_index)

    def _emit_activated(self, index) -> None:
        record = record_for_index(self._proxy, index)
        if record is not None:
            self.record_activated.emit(record)

    def _show_context_menu(self, position) -> None:
        index = self.table.indexAt(position)
        record = record_for_index(self._proxy, index) if index.isValid() else None
        menu = QMenu(self)
        inspect_action = menu.addAction("Inspect packet")
        copy_txn = menu.addAction("Copy transaction ID")
        copy_source = menu.addAction("Copy source endpoint")
        copy_destination = menu.addAction("Copy destination endpoint")
        menu.addSeparator()
        clear_action = menu.addAction("Clear table")
        chosen = menu.exec(self.table.viewport().mapToGlobal(position))
        if chosen is None:
            return
        if chosen == inspect_action and record is not None:
            self.record_activated.emit(record)
        elif chosen == copy_txn and record is not None:
            QGuiApplication.clipboard().setText(record.transaction_id())
        elif chosen == copy_source and record is not None:
            QGuiApplication.clipboard().setText(f"{record.src_ip}:{record.src_port}")
        elif chosen == copy_destination and record is not None:
            QGuiApplication.clipboard().setText(f"{record.dst_ip}:{record.dst_port}")
        elif chosen == clear_action:
            self._confirm_clear()
