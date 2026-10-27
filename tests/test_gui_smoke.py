"""GUI smoke tests: module imports, theme, and window construction.

These run only where PySide6 is installed (CI does this with the
``offscreen`` Qt platform) and validate that the GUI layer imports and
constructs correctly without any display, Npcap, or Administrator
privileges. Deep widget interaction is out of scope here.
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


def test_every_gui_module_imports():
    from stunscope.gui import logging_bridge, main, main_window, models, theme, workers
    from stunscope.gui.pages import (
        CapturePage,
        DashboardPage,
        ExportPage,
        FiltersPage,
        InspectorPage,
        SettingsPage,
    )
    from stunscope.gui import widgets

    assert callable(main.run)
    assert callable(theme.apply_theme)
    assert CapturePage and DashboardPage and ExportPage and FiltersPage
    assert InspectorPage and SettingsPage
    assert widgets.StatCard and widgets.EmptyState


def test_theme_applies_to_app(qapp):
    from stunscope.gui.theme import apply_theme

    apply_theme(qapp)
    assert qapp.styleSheet()  # a stylesheet was installed


def test_shared_model_and_proxy(qapp):
    from stunscope.filters import PacketFilter
    from stunscope.gui.models import FilterProxyModel, PacketTableModel

    model = PacketTableModel(max_rows=100)
    proxy = FilterProxyModel()
    proxy.setSourceModel(model)
    proxy.set_packet_filter(PacketFilter())
    assert model.rowCount() == 0
    model.add_packets([])
    assert model.rowCount() == 0


def test_main_window_constructs(qapp):
    from stunscope.gui.main_window import MainWindow

    window = MainWindow()
    assert window.packet_model is not None
    assert window.proxy_model.sourceModel() is window.packet_model
    window.switch_page("capture")
    window.switch_page("inspector")
    window.switch_page("settings")
    window.close()
