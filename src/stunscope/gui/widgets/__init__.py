"""Reusable visual widgets for the STUNScope desktop interface."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

STATUS_COLORS = {
    "idle": "#8b95a7",
    "running": "#57c785",
    "stopping": "#e5b567",
    "error": "#e5697a",
    "paused": "#e5b567",
}


class SectionLabel(QLabel):
    """Small uppercase section heading."""

    def __init__(self, text: str, parent=None) -> None:
        super().__init__(text, parent)
        self.setObjectName("SectionLabel")


class Card(QFrame):
    """Bordered surface panel."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")


class StatCard(QFrame):
    """Dashboard metric card: title, big value, optional hint."""

    def __init__(self, title: str, value: str = "0", hint: str = "", parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("StatCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(2)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("StatCardTitle")
        self.value_label = QLabel(value)
        self.value_label.setObjectName("StatCardValue")
        self.hint_label = QLabel(hint)
        self.hint_label.setObjectName("StatCardHint")
        self.hint_label.setVisible(bool(hint))

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.hint_label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)

    def set_hint(self, hint: str) -> None:
        self.hint_label.setText(hint)
        self.hint_label.setVisible(bool(hint))


class StatusBadge(QWidget):
    """Capture status pill with a colored dot."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.dot = QLabel("●")
        self.text = QLabel("Idle")
        layout.addWidget(self.dot)
        layout.addWidget(self.text)
        self.set_state("idle", "Idle")

    def set_state(self, state: str, label: str) -> None:
        color = STATUS_COLORS.get(state, STATUS_COLORS["idle"])
        self.dot.setStyleSheet(f"color: {color}; font-size: 11px;")
        self.text.setText(label)
        self.text.setStyleSheet(f"color: {color}; font-weight: 600;")


class EmptyState(QWidget):
    """Centered placeholder shown when no packets are available."""

    def __init__(self, title: str, hint: str, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addStretch(1)

        title_label = QLabel(title)
        title_label.setObjectName("EmptyStateTitle")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint_label = QLabel(hint)
        hint_label.setObjectName("EmptyStateHint")
        hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint_label.setWordWrap(True)

        layout.addWidget(title_label)
        layout.addWidget(hint_label)
        layout.addStretch(1)
