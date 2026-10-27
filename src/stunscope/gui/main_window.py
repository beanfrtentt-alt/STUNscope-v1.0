"""Main STUNScope window: sidebar navigation, shared state, capture control."""

from __future__ import annotations

import time
from typing import Optional

from PySide6.QtCore import QThread, QTimer
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from stunscope.config import load_settings
from stunscope.filters import PacketFilter
from stunscope.gui.models import FilterProxyModel, PacketTableModel
from stunscope.gui.pages import (
    CapturePage,
    DashboardPage,
    ExportPage,
    FiltersPage,
    InspectorPage,
    SettingsPage,
)
from stunscope.gui.widgets import StatusBadge
from stunscope.gui.workers import CaptureWorker
from stunscope.logging_config import get_logger

logger = get_logger("gui")

_NAV_ITEMS = [
    ("dashboard", "Dashboard"),
    ("capture", "Live Capture"),
    ("inspector", "Packet Inspector"),
    ("filters", "Filters"),
    ("export", "Export"),
    ("settings", "Settings"),
]


class MainWindow(QMainWindow):
    """Owns the shared model/filter and hosts every page."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("STUNScope — STUN Packet Analyzer")
        self.resize(1180, 720)

        # shared, non-GUI state
        self.settings = load_settings()
        self.packet_filter = PacketFilter()

        # shared GUI state
        self.packet_model = PacketTableModel(max_rows=self.settings.max_display_rows)
        self.proxy_model = FilterProxyModel()
        self.proxy_model.setSourceModel(self.packet_model)
        self.proxy_model.set_packet_filter(self.packet_filter)

        # capture machinery
        self._worker: Optional[CaptureWorker] = None
        self._worker_thread: Optional[QThread] = None
        self._capture_started_at: float = 0.0
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(1000)
        self._elapsed_timer.timeout.connect(self._tick_elapsed)

        self._build_ui()
        self._populate_interfaces()

    # ------------------------------------------------------------------ UI --
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---------- sidebar ----------
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(210)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(0, 18, 0, 18)
        side.setSpacing(4)

        brand = QLabel("STUNScope")
        brand.setObjectName("HeaderTitle")
        brand.setContentsMargins(18, 0, 0, 12)
        side.addWidget(brand)

        self.nav_buttons: dict[str, QPushButton] = {}
        for key, label in _NAV_ITEMS:
            button = QPushButton(label)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, k=key: self.switch_page(k))
            self.nav_buttons[key] = button
            side.addWidget(button)
        side.addStretch(1)

        notice = QLabel(
            "Authorized diagnostics only.\nCapture may require Administrator privileges."
        )
        notice.setObjectName("MutedText")
        notice.setWordWrap(True)
        notice.setContentsMargins(18, 0, 18, 0)
        side.addWidget(notice)
        root.addWidget(sidebar)

        # ---------- right column ----------
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 14, 20, 14)
        title = QLabel("STUNScope")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("STUN (RFC 8489) packet analyzer for authorized test sessions")
        subtitle.setObjectName("HeaderSubtitle")
        self.status_badge = StatusBadge()
        self.elapsed_label = QLabel("")
        self.elapsed_label.setObjectName("MutedText")
        header_layout.addWidget(title)
        header_layout.addSpacing(10)
        header_layout.addWidget(subtitle)
        header_layout.addStretch(1)
        header_layout.addWidget(self.elapsed_label)
        header_layout.addSpacing(12)
        header_layout.addWidget(self.status_badge)
        right_layout.addWidget(header)

        # ---------- pages ----------
        self.pages = QStackedWidget()
        self.dashboard_page = DashboardPage()
        self.capture_page = CapturePage(
            self.packet_model, self.proxy_model, self.packet_filter
        )
        self.inspector_page = InspectorPage(self.packet_model, self.proxy_model)
        self.filters_page = FiltersPage(self.packet_filter)
        self.export_page = ExportPage(
            self.packet_model, self.proxy_model, self.packet_filter, self.settings
        )
        self.settings_page = SettingsPage(self.settings)

        self.pages.addWidget(self.dashboard_page)
        self.pages.addWidget(self.capture_page)
        self.pages.addWidget(self.inspector_page)
        self.pages.addWidget(self.filters_page)
        self.pages.addWidget(self.export_page)
        self.pages.addWidget(self.settings_page)
        right_layout.addWidget(self.pages, stretch=1)
        root.addWidget(right, stretch=1)

        # ---------- status bar ----------
        status = QStatusBar()
        self.setStatusBar(status)
        status.showMessage(
            "Capture reads only traffic on the selected interface. Only analyze "
            "networks you own or are authorized to test."
        )

        # ---------- cross-page wiring ----------
        self.packet_model.stats_changed.connect(self._on_stats_changed)
        self.packet_model.rows_changed.connect(lambda _total: self._refresh_dependents())
        self.capture_page.start_requested.connect(self._start_capture)
        self.capture_page.stop_requested.connect(self._stop_capture)
        self.capture_page.filter_changed.connect(self._on_filter_changed)
        self.capture_page.record_activated.connect(self._inspect_record)
        self.filters_page.filter_changed.connect(self._on_filter_changed)
        self.filters_page.reset_requested.connect(self.capture_page.sync_from_filter)
        self.settings_page.settings_changed.connect(self._on_settings_changed)
        self.inspector_page.attach_selection_model(self.capture_page.table)

        self._on_stats_changed(self.packet_model.stats)
        self._update_badge("idle", "Idle")
        self.switch_page("dashboard")

    # ------------------------------------------------------------- interface --
    def _populate_interfaces(self) -> None:
        """Load interfaces in the background of startup; degrade gracefully."""
        try:
            from stunscope.capture import list_interfaces

            interfaces = list_interfaces()
        except Exception as exc:  # CaptureUnavailableError or import problems
            logger.warning("interface listing failed: %s", exc)
            self.capture_page.set_interfaces([], error=str(exc))
            self.settings_page.set_interface_choices([])
            return
        choices = [(iface.name, iface.description) for iface in interfaces]
        self.capture_page.set_interfaces(choices)
        self.settings_page.set_interface_choices([iface.description for iface in interfaces])
        saved = self.settings.default_interface
        if saved:
            for name, description in choices:
                if description == saved:
                    self.capture_page.select_interface(name)
                    break

    # ------------------------------------------------------------- navigation --
    def switch_page(self, key: str) -> None:
        index = dict(
            dashboard=0, capture=1, inspector=2, filters=3, export=4, settings=5
        ).get(key, 0)
        self.pages.setCurrentIndex(index)
        for button_key, button in self.nav_buttons.items():
            button.setChecked(button_key == key)
        if key == "export":
            self.export_page.sync_filter_description()

    # ---------------------------------------------------------------- capture --
    def _start_capture(self, parameters: dict) -> None:
        if self._worker is not None:
            return
        name = parameters.get("interface_name", "")
        _selected_name, label = self.capture_page.current_interface()
        worker = CaptureWorker(
            interface_name=name,
            interface_label=label or name,
            ports=parameters.get("ports") or None,
            duration=parameters.get("duration"),
            max_packets=parameters.get("max_packets"),
        )
        thread = QThread(self)
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.batch_ready.connect(self.packet_model.add_packets)
        worker.status_updated.connect(self._on_capture_status)
        worker.started_capture.connect(self._on_capture_started)
        worker.stopped_capture.connect(self._on_capture_finished)
        worker.capture_failed.connect(self._on_capture_failed)

        self._worker = worker
        self._worker_thread = thread
        self._capture_started_at = time.time()
        thread.start()

    def _stop_capture(self) -> None:
        if self._worker is None:
            return
        self._update_badge("stopping", "Stopping…")
        self._worker.request_stop()

    def _on_capture_started(self, label: str) -> None:
        self._update_badge("running", "Capturing")
        self.capture_page.set_capture_state(True)
        self.dashboard_page.update_capture_status(
            "running", "Capturing", label
        )
        self._elapsed_timer.start()
        logger.info("capture started on %s", label)

    def _on_capture_status(self, emitted: int) -> None:
        self.elapsed_label.setText(f"{emitted} STUN messages")

    def _on_capture_finished(self, stats: dict) -> None:
        self._teardown_worker()
        self._update_badge("idle", "Idle")
        self.capture_page.set_capture_state(False)
        self._elapsed_timer.stop()
        duration = stats.get("duration", 0.0)
        self.dashboard_page.update_capture_status(
            "idle", f"Stopped — {duration:.0f}s, {stats.get('records_emitted', 0)} messages", ""
        )
        if stats.get("dropped"):
            logger.info("dropped %d buffered packets (worker cap)", stats["dropped"])
        logger.info("capture finished: %s", stats)

    def _on_capture_failed(self, message: str) -> None:
        self._teardown_worker()
        self._update_badge("error", "Capture failed")
        self.capture_page.set_capture_state(False)
        self._elapsed_timer.stop()
        QMessageBox.critical(
            self,
            "Capture failed",
            f"{message}\n\nOn Windows, most capture problems are solved by "
            "installing Npcap (with “WinPcap API-compatible Mode”) and running "
            "STUNScope from an Administrator terminal. See "
            "docs/troubleshooting.md.",
        )
        self.dashboard_page.update_capture_status("error", "Capture failed", "")
        logger.error("capture failed: %s", message)

    def _teardown_worker(self) -> None:
        worker, thread = self._worker, self._worker_thread
        self._worker = None
        self._worker_thread = None
        if thread is not None:
            thread.quit()
            thread.wait(3000)
        if worker is not None:
            worker.deleteLater()

    # ---------------------------------------------------------------- signals --
    def _on_stats_changed(self, stats: dict) -> None:
        self.dashboard_page.update_stats(stats)

    def _on_filter_changed(self) -> None:
        self.proxy_model.refresh()
        self.export_page.sync_filter_description()

    def _refresh_dependents(self) -> None:
        self.capture_page._on_rows_changed(self.packet_model.row_count())

    def _inspect_record(self, record) -> None:
        self.inspector_page.set_record(record)
        self.switch_page("inspector")

    def _on_settings_changed(self) -> None:
        self.packet_model.set_max_rows(self.settings.max_rows())
        # ExportPage reads settings directly; nothing else to do here.

    def _update_badge(self, state: str, label: str) -> None:
        self.status_badge.set_state(state, label)

    def _tick_elapsed(self) -> None:
        if self._capture_started_at:
            elapsed = time.time() - self._capture_started_at
            self.dashboard_page.update_duration(elapsed)
            minutes, seconds = divmod(int(elapsed), 60)
            self.status_badge.set_state("running", f"Capturing · {minutes:02d}:{seconds:02d}")

    # ---------------------------------------------------------------- shutdown --
    def closeEvent(self, event) -> None:  # noqa: N802 (Qt naming)
        if self._worker is not None:
            answer = QMessageBox.question(
                self,
                "Capture still running",
                "A capture is active. Stop it and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Yes,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._worker.request_stop()
            self._teardown_worker()
        super().closeEvent(event)
