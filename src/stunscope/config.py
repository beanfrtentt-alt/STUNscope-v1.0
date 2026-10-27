"""Application configuration shared by the CLI and the GUI.

Settings are stored as a small JSON document in a platform-appropriate
location:

- Windows: ``%APPDATA%\\STUNScope\\settings.json``
- Other platforms: ``~/.config/stunscope/settings.json``

Only user-interface preferences live here. STUNScope stores no capture
history on disk by default, and ``clear_stored_data()`` removes everything
the app has persisted (settings plus rotated log files).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

APP_NAME = "STUNScope"
DEFAULT_MAX_DISPLAY_ROWS = 5000

_SETTING_KEYS = {
    "default_interface",
    "default_export_dir",
    "redact_addresses",
    "max_display_rows",
    "auto_scroll",
}


def config_dir() -> Path:
    """Platform configuration directory (created on demand)."""
    if os.name == "nt" and os.environ.get("APPDATA"):
        base = Path(os.environ["APPDATA"])
    else:
        base = Path.home() / ".config"
    directory = base / APP_NAME
    return directory


def logs_dir() -> Path:
    return config_dir() / "logs"


def settings_path() -> Path:
    return config_dir() / "settings.json"


def default_export_dir() -> Path:
    return Path.home() / "Documents" / "STUNScope Exports"


@dataclass
class AppSettings:
    """User preferences. Never contains capture data or credentials."""

    default_interface: str = ""
    default_export_dir: str = ""
    redact_addresses: bool = False
    max_display_rows: int = DEFAULT_MAX_DISPLAY_ROWS
    auto_scroll: bool = True

    def resolved_export_dir(self) -> Path:
        if self.default_export_dir:
            return Path(self.default_export_dir)
        return default_export_dir()

    def max_rows(self) -> int:
        return max(100, min(100_000, int(self.max_display_rows)))


def load_settings() -> AppSettings:
    """Load settings, falling back to defaults on any problem."""
    path = settings_path()
    if not path.exists():
        return AppSettings(default_export_dir=str(default_export_dir()))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("settings root is not an object")
        cleaned = {k: v for k, v in data.items() if k in _SETTING_KEYS}
        settings = AppSettings(**cleaned)
    except (OSError, ValueError, TypeError):
        # A corrupt settings file must never prevent the app from starting.
        return AppSettings(default_export_dir=str(default_export_dir()))
    if not settings.default_export_dir:
        settings.default_export_dir = str(default_export_dir())
    return settings


def save_settings(settings: AppSettings) -> Path:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {k: v for k, v in asdict(settings).items() if k in _SETTING_KEYS}
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def clear_stored_data() -> list[str]:
    """Remove every file STUNScope has persisted. Returns what was removed."""
    removed: list[str] = []
    settings = settings_path()
    try:
        if settings.exists():
            settings.unlink()
            removed.append(str(settings))
    except OSError:
        pass
    logs = logs_dir()
    if logs.exists():
        for item in logs.iterdir():
            try:
                if item.is_file():
                    item.unlink()
                    removed.append(str(item))
            except OSError:
                pass
    return removed


def reset_logs_dir() -> Path:
    """Recreate the log directory after a wipe (used by the GUI)."""
    directory = logs_dir()
    directory.mkdir(parents=True, exist_ok=True)
    return directory
