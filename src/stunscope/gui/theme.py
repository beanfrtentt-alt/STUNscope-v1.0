"""Dark theme: slate surfaces, restrained purple accent, neutral text."""

from __future__ import annotations

COLORS = {
    "bg": "#0e1116",
    "surface": "#161b24",
    "surface_alt": "#1a2130",
    "border": "#262d3a",
    "text": "#e7eaf0",
    "muted": "#8b95a7",
    "accent": "#8b7cf6",
    "accent_hover": "#a79df9",
    "accent_pressed": "#6d64d8",
    "accent_dim": "#2a2a4d",
    "success": "#57c785",
    "warning": "#e5b567",
    "error": "#e5697a",
    "table_base": "#12161f",
    "table_alt": "#171c28",
}

_STYLESHEET = """
QWidget {{
    background-color: {bg};
    color: {text};
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}}

QMainWindow::separator {{ background: {border}; width: 1px; }}

/* ---------- sidebar ---------- */
#Sidebar {{
    background-color: #0b0e13;
    border-right: 1px solid {border};
}}
QPushButton#NavButton {{
    text-align: left;
    padding: 10px 16px;
    border: none;
    border-left: 3px solid transparent;
    border-radius: 0;
    color: {muted};
    background: transparent;
    font-size: 13px;
}}
QPushButton#NavButton:hover {{ color: {text}; background: {surface}; }}
QPushButton#NavButton:checked {{
    color: {text};
    background: {surface_alt};
    border-left: 3px solid {accent};
    font-weight: 600;
}}

/* ---------- header ---------- */
#HeaderTitle {{ font-size: 20px; font-weight: 700; color: {text}; }}
#HeaderSubtitle {{ color: {muted}; font-size: 12px; }}

/* ---------- cards ---------- */
QFrame#Card {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 10px;
}}
QFrame#StatCard {{
    background-color: {surface};
    border: 1px solid {border};
    border-left: 3px solid {accent};
    border-radius: 10px;
}}
QLabel#StatCardTitle {{ color: {muted}; font-size: 11px; letter-spacing: 1px; }}
QLabel#StatCardValue {{ font-size: 22px; font-weight: 700; }}
QLabel#StatCardHint {{ color: {muted}; font-size: 11px; }}
QLabel#SectionLabel {{
    color: {muted};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
    padding: 2px 0;
}}

/* ---------- inputs ---------- */
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background-color: {table_base};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: {accent_dim};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {accent};
}}
QLineEdit::placeholder {{ color: #5c6577; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background-color: {surface};
    border: 1px solid {border};
    selection-background-color: {accent_dim};
    selection-color: {text};
}}

/* ---------- buttons ---------- */
QPushButton {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 600;
}}
QPushButton:hover {{ background-color: {surface_alt}; }}
QPushButton:disabled {{ color: #555e70; background-color: {surface}; }}
QPushButton#Primary {{
    background-color: {accent};
    border: none;
    color: #14141f;
}}
QPushButton#Primary:hover {{ background-color: {accent_hover}; }}
QPushButton#Primary:pressed {{ background-color: {accent_pressed}; }}
QPushButton#Primary:disabled {{ background-color: #3d3a58; color: #7b7994; }}
QPushButton#Danger {{ border-color: #5a3340; color: {error}; }}
QPushButton#Danger:hover {{ background-color: #2a1d24; }}

/* ---------- tables ---------- */
QTableView {{
    background-color: {table_base};
    alternate-background-color: {table_alt};
    border: 1px solid {border};
    border-radius: 6px;
    gridline-color: #1d2330;
    selection-background-color: {accent_dim};
    selection-color: {text};
}}
QHeaderView::section {{
    background-color: {surface};
    color: {muted};
    border: none;
    border-right: 1px solid {border};
    border-bottom: 1px solid {border};
    padding: 6px 8px;
    font-size: 11px;
    font-weight: 600;
}}
QTableCornerButton::section {{ background-color: {surface}; border: none; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{
    background: {border}; border-radius: 4px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {accent_dim}; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {border}; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* ---------- misc ---------- */
QToolTip {{
    background-color: {surface};
    color: {text};
    border: 1px solid {border};
    padding: 6px 8px;
}}
QTextEdit#RawDump {{
    background-color: #0b0e13;
    border: 1px solid {border};
    border-radius: 6px;
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
    color: {muted};
}}
QLabel#EmptyStateTitle {{ font-size: 16px; font-weight: 600; color: {text}; }}
QLabel#EmptyStateHint {{ color: {muted}; }}
QFrame#WarningBanner {{
    background-color: #2a221a;
    border: 1px solid #4a3a24;
    border-radius: 6px;
}}
QLabel#ErrorText {{ color: {error}; }}
QLabel#SuccessText {{ color: {success}; }}
QLabel#MutedText {{ color: {muted}; }}
QStatusBar {{ background: #0b0e13; border-top: 1px solid {border}; color: {muted}; }}
QRadioButton {{ spacing: 8px; }}
QCheckBox {{ spacing: 8px; }}
QMenu {{
    background-color: {surface};
    border: 1px solid {border};
}}
QMenu::item {{ padding: 6px 24px; }}
QMenu::item:selected {{ background-color: {accent_dim}; }}
"""


def apply_theme(app) -> None:
    """Install the STUNScope dark palette and stylesheet on a QApplication."""
    from PySide6.QtGui import QPalette, QColor

    app.setStyle("Fusion")

    palette = QPalette()
    role = QPalette.ColorRole
    group_disabled = QPalette.ColorGroup.Disabled

    def color(name: str) -> QColor:
        return QColor(COLORS[name])

    palette.setColor(role.Window, color("bg"))
    palette.setColor(role.WindowText, color("text"))
    palette.setColor(role.Base, color("table_base"))
    palette.setColor(role.AlternateBase, color("table_alt"))
    palette.setColor(role.Text, color("text"))
    palette.setColor(role.Button, color("surface"))
    palette.setColor(role.ButtonText, color("text"))
    palette.setColor(role.Highlight, color("accent_dim"))
    palette.setColor(role.HighlightedText, color("text"))
    palette.setColor(role.ToolTipBase, color("surface"))
    palette.setColor(role.ToolTipText, color("text"))
    palette.setColor(role.Link, color("accent_hover"))
    palette.setColor(role.PlaceholderText, QColor("#5c6577"))

    palette.setColor(group_disabled, role.Text, QColor("#555e70"))
    palette.setColor(group_disabled, role.ButtonText, QColor("#555e70"))
    palette.setColor(group_disabled, role.WindowText, QColor("#555e70"))

    # Explicit dark tooltips on Windows where the native hint wins.
    palette.setColor(QPalette.ColorGroup.Active, role.ToolTipBase, color("surface"))
    palette.setColor(QPalette.ColorGroup.Active, role.ToolTipText, color("text"))

    app.setPalette(palette)
    app.setStyleSheet(_STYLESHEET.format(**COLORS))
