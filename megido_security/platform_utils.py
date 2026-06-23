"""Cross-platform filesystem and process helpers for Megido."""

from __future__ import annotations

import ctypes
import importlib.util
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


def is_running_in_docker() -> bool:
    """Return True if the process is running inside a Docker/container environment.

    Checks (in order):

    1. ``/.dockerenv`` file – present in every Docker container.
    2. ``/proc/1/cgroup`` – contains "docker" or "containerd" on Linux.
    3. ``DOCKER_CONTAINER`` or ``container`` environment variables.
    """
    if os.path.exists("/.dockerenv"):
        return True
    # /proc/1/cgroup only exists on Linux; skip silently on other platforms.
    try:
        with open("/proc/1/cgroup", "r", encoding="utf-8") as fh:
            content = fh.read()
            if "docker" in content or "containerd" in content:
                return True
    except OSError:
        pass
    if os.environ.get("DOCKER_CONTAINER") or os.environ.get("container"):
        return True
    return False


def display_available() -> bool:
    """Return True if a graphical display is reachable on this system.

    Windows and macOS always have a display context; on Linux/BSD a
    ``DISPLAY`` (X11) or ``WAYLAND_DISPLAY`` environment variable must be set.
    """
    system = platform.system()
    if system in {"Windows", "Darwin"}:
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def desktop_stack_available() -> bool:
    """Return True if the full desktop-browser stack can run on this system.

    Requires all of the following:
    - A graphical display (see :func:`display_available`).
    - Not running inside a Docker/container environment.
    - ``PyQt6`` and ``PyQt6.QtWebEngineWidgets`` importable.
    """
    if not display_available():
        return False
    if is_running_in_docker():
        return False
    for mod in ("PyQt6.QtWidgets", "PyQt6.QtWebEngineWidgets"):
        if importlib.util.find_spec(mod) is None:
            return False
    return True


def mitmdump_available() -> bool:
    """Return True if ``mitmdump`` is available on PATH."""
    return find_executable("mitmdump") is not None


def is_admin() -> bool:
    system = platform.system()
    if system == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    if hasattr(os, "geteuid"):
        return os.geteuid() == 0

    return False
