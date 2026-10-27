"""Dashboard: live totals and capture status at a glance."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from stunscope.gui.widgets import Card, EmptyState, SectionLabel, StatCard, StatusBadge


class DashboardPage(QWidget):
    """Overview cards fed by the shared packet model."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        header = QHBoxLayout()
        title = QLabel("Dashboard")
        title.setObjectName("HeaderTitle")
        self.badge = StatusBadge()
        self.interface_label = QLabel("No interface selected")
        self.interface_label.setObjectName("MutedText")
        header.addWidget(title)
        header.addStretch(1)
        header.addWidget(self.interface_label)
        header.addSpacing(16)
        header.addWidget(self.badge)
        layout.addLayout(header)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.cards: dict[str, StatCard] = {}

        definitions = [
            ("packets", "PACKETS CAPTURED", "STUN messages parsed"),
            ("valid", "VALID STUN MESSAGES", "parsed without protocol errors"),
            ("requests", "BINDING REQUESTS", "clients asking for a mapping"),
            ("success", "BINDING SUCCESS RESPONSES", "server-observed mapped address"),
            ("errors", "BINDING ERROR RESPONSES", "e.g. 401 Unauthorized, 420"),
            ("malformed", "MALFORMED MESSAGES", "framing/attribute violations"),
            ("duration", "CAPTURE DURATION", "wall-clock time of last capture"),
            ("interface", "INTERFACE & STATUS", "current capture device"),
        ]
        for index, (key, title_text, hint) in enumerate(definitions):
            card = StatCard(title_text, "0", hint)
            self.cards[key] = card
            grid.addWidget(card, index // 4, index % 4)

        layout.addLayout(grid)

        self.empty_state = EmptyState(
            "No packets captured yet",
            "Start a capture from the Live Capture page, then statistics will "
            "appear here in real time.",
        )
        layout.addWidget(self.empty_state, stretch=1)

        note = Card()
        note_layout = QHBoxLayout(note)
        note_layout.setContentsMargins(16, 12, 16, 12)
        note_text = QLabel(
            "A mapped address in a Binding response is the address the STUN server "
            "observed for the request sender (usually your NAT binding). It does not, "
            "by itself, identify a remote call participant."
        )
        note_text.setWordWrap(True)
        note_text.setObjectName("MutedText")
        note_layout.addWidget(note_text)
        layout.addWidget(note)

    # -- public API (called by MainWindow) ------------------------------------
    def update_stats(self, stats: dict) -> None:
        self.cards["packets"].set_value(str(stats.get("total", 0)))
        self.cards["valid"].set_value(str(stats.get("valid", 0)))
        self.cards["requests"].set_value(str(stats.get("binding_requests", 0)))
        self.cards["success"].set_value(str(stats.get("binding_success", 0)))
        self.cards["errors"].set_value(str(stats.get("binding_errors", 0)))
        self.cards["malformed"].set_value(str(stats.get("malformed", 0)))
        dropped = stats.get("dropped", 0)
        if dropped:
            self.cards["packets"].set_hint(
                f"{dropped} oldest packets dropped to respect the display cap"
            )
        self.empty_state.setVisible(stats.get("total", 0) == 0)

    def update_capture_status(self, state: str, label: str, interface: str) -> None:
        self.badge.set_state(state, label)
        self.interface_label.setText(interface or "No interface selected")
        self.cards["interface"].set_value(interface or "—")
        self.cards["interface"].set_hint(label)

    def update_duration(self, seconds: float) -> None:
        minutes, secs = divmod(int(seconds), 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            self.cards["duration"].set_value(f"{hours}h {minutes:02d}m {secs:02d}s")
        else:
            self.cards["duration"].set_value(f"{minutes:02d}m {secs:02d}s")
