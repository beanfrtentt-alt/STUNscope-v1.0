"""Export page: CSV writing with optional privacy redaction."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from stunscope.config import AppSettings
from stunscope.exporter import export_csv
from stunscope.filters import PacketFilter
from stunscope.gui.models import FilterProxyModel, PacketTableModel
from stunscope.gui.widgets import Card


class ExportPage(QWidget):
    """Choose a destination and write a UTF-8 CSV of captured records."""

    export_finished = Signal(bool, str)

    def __init__(
        self,
        model: PacketTableModel,
        proxy: FilterProxyModel,
        packet_filter: PacketFilter,
        settings: AppSettings,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._model = model
        self._proxy = proxy
        self._filter = packet_filter
        self._settings = settings

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        title = QLabel("Export")
        title.setObjectName("HeaderTitle")
        layout.addWidget(title)

        card = Card()
        form = QVBoxLayout(card)
        form.setContentsMargins(18, 16, 18, 16)
        form.setSpacing(12)

        directory_row = QHBoxLayout()
        self.directory_edit = QLineEdit(str(self._settings.resolved_export_dir()))
        self.directory_edit.setMinimumWidth(360)
        browse_button = QPushButton("Browse…")
        browse_button.clicked.connect(self._browse_directory)
        directory_row.addWidget(QLabel("Directory"))
        directory_row.addWidget(self.directory_edit, stretch=1)
        directory_row.addWidget(browse_button)
        form.addLayout(directory_row)

        filename_row = QHBoxLayout()
        self.filename_edit = QLineEdit("stunscope-export.csv")
        filename_row.addWidget(QLabel("File name"))
        filename_row.addWidget(self.filename_edit)
        form.addLayout(filename_row)

        scope_row = QHBoxLayout()
        self.radio_all = QRadioButton("All captured packets")
        self.radio_filtered = QRadioButton("Filtered packets only")
        self.radio_all.setChecked(True)
        scope_row.addWidget(self.radio_all)
        scope_row.addWidget(self.radio_filtered)
        scope_row.addStretch(1)
        form.addLayout(scope_row)

        self.redact_check = QCheckBox(
            "Privacy mode: redact IP addresses (IPv4 → /24, IPv6 → /64)"
        )
        self.redact_check.setChecked(self._settings.redact_addresses)
        self.redact_check.setToolTip(
            "Masked addresses still show the network but not the host. Exports are "
            "written locally and never transmitted anywhere."
        )
        form.addWidget(self.redact_check)

        button_row = QHBoxLayout()
        self.export_button = QPushButton("Export CSV")
        self.export_button.setObjectName("Primary")
        button_row.addWidget(self.export_button)
        button_row.addStretch(1)
        form.addLayout(button_row)

        layout.addWidget(card)

        self.info_label = QLabel(
            "One CSV row is written per decoded attribute (packets without "
            "attributes produce one message row). Fields that do not apply to a "
            "row are written as “n/a”; genuinely empty values stay empty."
        )
        self.info_label.setObjectName("MutedText")
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        self.result_label = QLabel("")
        self.result_label.setWordWrap(True)
        layout.addWidget(self.result_label)
        layout.addStretch(1)

        self._settings_watcher = None  # set by MainWindow if needed
        self.export_button.clicked.connect(self._do_export)

    # -- public -----------------------------------------------------------
    def sync_filter_description(self) -> None:
        self.radio_filtered.setToolTip(self._filter.describe())
        self.radio_filtered.setEnabled(self._filter.is_active())
        if not self._filter.is_active():
            self.radio_all.setChecked(True)

    # -- internals -----------------------------------------------------------
    def _browse_directory(self) -> None:
        current = self.directory_edit.text() or str(Path.home())
        directory = QFileDialog.getExistingDirectory(
            self, "Choose export directory", current
        )
        if directory:
            self.directory_edit.setText(directory)

    def _do_export(self) -> None:
        directory = Path(self.directory_edit.text().strip()).expanduser()
        filename = self.filename_edit.text().strip() or "stunscope-export.csv"
        destination = directory / filename
        if not directory.exists():
            self._show_result(False, f"Directory does not exist: {directory}")
            return
        if destination.exists():
            answer = self._confirm_overwrite(destination)
            if not answer:
                return

        records = (
            self._model.all_records()
            if self.radio_all.isChecked()
            else self._proxy.filtered_records()
        )
        if not records:
            self._show_result(
                False, "Nothing to export yet — capture some packets first."
            )
            return

        result = export_csv(
            records,
            destination,
            redact_addresses=self.redact_check.isChecked(),
        )
        if result.success:
            self._settings.redact_addresses = self.redact_check.isChecked()
            self._settings.default_export_dir = str(directory)
            self._show_result(
                True,
                f"Exported {result.rows_written} rows ({result.packet_count} packets) "
                f"to {result.path}",
            )
            self.export_finished.emit(True, str(result.path))
        else:
            self._show_result(False, result.error)

    def _confirm_overwrite(self, destination: Path) -> bool:
        from PySide6.QtWidgets import QMessageBox

        answer = QMessageBox.question(
            self,
            "Overwrite existing file?",
            f"{destination} already exists. Overwrite it?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    def _show_result(self, ok: bool, text: str) -> None:
        self.result_label.setObjectName("SuccessText" if ok else "ErrorText")
        self.result_label.setText(("✓ " if ok else "✗ ") + text)
        # Force style re-evaluation after objectName change.
        self.result_label.style().unpolish(self.result_label)
        self.result_label.style().polish(self.result_label)
