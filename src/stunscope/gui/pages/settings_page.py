"""Settings page: persisted preferences and data management."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from stunscope import __version__
from stunscope.config import (
    AppSettings,
    clear_stored_data,
    save_settings,
)
from stunscope.gui.widgets import Card, SectionLabel
from stunscope.logging_config import get_logger

logger = get_logger("gui.settings")


class SettingsPage(QWidget):
    """Display and persistence preferences; everything saves immediately."""

    settings_changed = Signal()

    def __init__(self, settings: AppSettings, parent=None) -> None:
        super().__init__(parent)
        self._settings = settings

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        title = QLabel("Settings")
        title.setObjectName("HeaderTitle")
        layout.addWidget(title)

        # ---- capture -------------------------------------------------------
        capture_card = Card()
        capture_layout = QVBoxLayout(capture_card)
        capture_layout.setContentsMargins(18, 16, 18, 16)
        capture_layout.setSpacing(10)
        capture_layout.addWidget(SectionLabel("DEFAULTS"))

        self.interface_combo = QComboBox()
        self.interface_combo.setEditable(True)
        self.interface_combo.setToolTip(
            "Interface pre-selected when the app starts. Type the description "
            "shown in Live Capture."
        )
        row = QHBoxLayout()
        row.addWidget(QLabel("Default interface"))
        row.addWidget(self.interface_combo, stretch=1)
        capture_layout.addLayout(row)

        export_row = QHBoxLayout()
        self.export_dir_edit = QLineEdit(str(self._settings.resolved_export_dir()))
        export_browse = QPushButton("Browse…")
        export_browse.clicked.connect(self._browse_export_dir)
        export_row.addWidget(QLabel("Default export directory"))
        export_row.addWidget(self.export_dir_edit, stretch=1)
        export_row.addWidget(export_browse)
        capture_layout.addLayout(export_row)

        max_rows_row = QHBoxLayout()
        self.max_rows_spin = QDoubleSpinBox()
        self.max_rows_spin.setDecimals(0)
        self.max_rows_spin.setRange(100, 100_000)
        self.max_rows_spin.setValue(float(self._settings.max_display_rows))
        self.max_rows_spin.setToolTip(
            "Upper bound on packets kept in memory during very long captures; "
            "the oldest rows are dropped once the cap is reached."
        )
        max_rows_row.addWidget(QLabel("Max packets in memory"))
        max_rows_row.addWidget(self.max_rows_spin)
        max_rows_row.addStretch(1)
        capture_layout.addLayout(max_rows_row)
        layout.addWidget(capture_card)

        # ---- display ---------------------------------------------------------
        display_card = Card()
        display_layout = QVBoxLayout(display_card)
        display_layout.setContentsMargins(18, 16, 18, 16)
        display_layout.setSpacing(10)
        display_layout.addWidget(SectionLabel("DISPLAY"))

        self.auto_scroll_check = QCheckBox("Auto-scroll the packet table to new packets")
        self.auto_scroll_check.setChecked(self._settings.auto_scroll)
        display_layout.addWidget(self.auto_scroll_check)

        self.redact_check = QCheckBox(
            "Redact IP addresses in exported CSV files by default (privacy mode)"
        )
        self.redact_check.setChecked(self._settings.redact_addresses)
        display_layout.addWidget(self.redact_check)
        layout.addWidget(display_card)

        # ---- data ------------------------------------------------------------
        data_card = Card()
        data_layout = QVBoxLayout(data_card)
        data_layout.setContentsMargins(18, 16, 18, 16)
        data_layout.setSpacing(10)
        data_layout.addWidget(SectionLabel("STORED DATA"))

        data_hint = QLabel(
            "STUNScope stores only user-interface settings and diagnostic logs "
            "(no packet history). “Clear stored capture data” removes the settings "
            "file and all log files; packets in the current session stay in memory "
            "until you close the app or clear the table."
        )
        data_hint.setObjectName("MutedText")
        data_hint.setWordWrap(True)
        data_layout.addWidget(data_hint)

        self.clear_button = QPushButton("Clear stored capture data")
        self.clear_button.setObjectName("Danger")
        data_layout.addWidget(self.clear_button)
        layout.addWidget(data_card)

        # ---- about ---------------------------------------------------------------
        about_card = Card()
        about_layout = QVBoxLayout(about_card)
        about_layout.setContentsMargins(18, 16, 18, 16)
        about_layout.addWidget(SectionLabel("ABOUT"))
        about_text = QLabel(
            f"STUNScope {__version__} — STUN (RFC 8489) packet analyzer for "
            "authorized network diagnostics. Intended for analyzing traffic on "
            "networks you own or are explicitly permitted to test. See "
            "docs/privacy-and-security.md for the full usage notice."
        )
        about_text.setObjectName("MutedText")
        about_text.setWordWrap(True)
        about_layout.addWidget(about_text)
        layout.addWidget(about_card)
        layout.addStretch(1)

        # wiring
        self.interface_combo.currentTextChanged.connect(self._save)
        self.export_dir_edit.textChanged.connect(self._save)
        self.max_rows_spin.valueChanged.connect(self._save)
        self.auto_scroll_check.toggled.connect(self._save)
        self.redact_check.toggled.connect(self._save)
        self.clear_button.clicked.connect(self._clear_stored_data)

    # -- public -----------------------------------------------------------
    def set_interface_choices(self, descriptions: list[str]) -> None:
        self.interface_combo.blockSignals(True)
        self.interface_combo.clear()
        self.interface_combo.addItems(descriptions)
        if self._settings.default_interface:
            index = self.interface_combo.findText(self._settings.default_interface)
            if index >= 0:
                self.interface_combo.setCurrentIndex(index)
            else:
                self.interface_combo.setEditText(self._settings.default_interface)
        self.interface_combo.blockSignals(False)

    # -- internals -----------------------------------------------------------
    def _browse_export_dir(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self, "Choose default export directory", self.export_dir_edit.text()
        )
        if directory:
            self.export_dir_edit.setText(directory)
            self._save()

    def _save(self, *_args) -> None:
        self._settings.default_interface = self.interface_combo.currentText().strip()
        self._settings.default_export_dir = self.export_dir_edit.text().strip()
        self._settings.max_display_rows = int(self.max_rows_spin.value())
        self._settings.auto_scroll = self.auto_scroll_check.isChecked()
        self._settings.redact_addresses = self.redact_check.isChecked()
        try:
            save_settings(self._settings)
        except OSError as exc:
            logger.warning("could not persist settings: %s", exc)
        self.settings_changed.emit()

    def _clear_stored_data(self) -> None:
        answer = QMessageBox.question(
            self,
            "Clear stored data?",
            "This removes the settings file and diagnostic logs from your user "
            "profile. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        removed = clear_stored_data()
        QMessageBox.information(
            self,
            "Stored data cleared",
            f"Removed {len(removed)} file(s)."
            + ("\n".join("\n  " + str(p) for p in removed[:8]) if removed else ""),
        )
        logger.info("cleared stored data: %s", len(removed))
