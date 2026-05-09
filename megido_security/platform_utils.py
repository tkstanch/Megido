"""Cross-platform filesystem and process helpers for Megido."""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import webbrowser
from pathlib import Path

from platformdirs import PlatformDirs

_DIRS = PlatformDirs(appname="Megido", appauthor="Megido", roaming=True)


def get_config_dir() -> Path:
    path = Path(_DIRS.user_config_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_data_dir() -> Path:
    path = Path(_DIRS.user_data_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_cache_dir() -> Path:
    path = Path(_DIRS.user_cache_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_log_dir() -> Path:
    path = get_data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def find_executable(name: str) -> str | None:
    return shutil.which(name)


def open_in_browser(url: str) -> bool:
    return webbrowser.open(url)


def open_file(path: str | Path) -> bool:
    resolved_path = Path(path).expanduser().resolve()
    if not resolved_path.exists():
        return False
    target = str(resolved_path)
    system = platform.system()

    try:
        if system == "Windows":
            os.startfile(target)  # type: ignore[attr-defined]
            return True
        if system == "Darwin":
            subprocess.run(["open", target], check=True)
            return True

        opener = find_executable("xdg-open")
        if opener:
            subprocess.run([opener, target], check=True)
            return True
    except (OSError, subprocess.SubprocessError, ValueError):
        return False

    return webbrowser.open(Path(target).as_uri())


def is_admin() -> bool:
    system = platform.system()
    if system == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    if hasattr(os, "geteuid"):
        return os.geteuid() == 0

    return False
