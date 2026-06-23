"""Unit tests for launch.py mode-selection and cross-platform detection logic."""

from __future__ import annotations

import argparse
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

import launch


# ---------------------------------------------------------------------------
# Helper: build a minimal Namespace that _run_web / _run_mode accept
# ---------------------------------------------------------------------------

def _args(**kwargs) -> argparse.Namespace:
    defaults = {"host": "127.0.0.1", "port": 8000, "use_sqlite": True, "no_sqlite": False}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# _display_available
# ---------------------------------------------------------------------------

class TestDisplayAvailable:
    def test_windows_always_true(self):
        with patch("launch.platform.system", return_value="Windows"):
            assert launch._display_available() is True

    def test_macos_always_true(self):
        with patch("launch.platform.system", return_value="Darwin"):
            assert launch._display_available() is True

    def test_linux_with_display(self):
        with patch("launch.platform.system", return_value="Linux"):
            with patch.dict("os.environ", {"DISPLAY": ":0"}, clear=False):
                assert launch._display_available() is True

    def test_linux_with_wayland(self):
        with patch("launch.platform.system", return_value="Linux"):
            with patch.dict("os.environ", {"WAYLAND_DISPLAY": "wayland-0"}, clear=False):
                assert launch._display_available() is True

    def test_linux_headless(self):
        with patch("launch.platform.system", return_value="Linux"):
            with patch.dict("os.environ", {}, clear=True):
                assert launch._display_available() is False


# ---------------------------------------------------------------------------
# _desktop_stack_available
# ---------------------------------------------------------------------------

class TestDesktopStackAvailable:
    def _patch_all(self, display=True, in_docker=False, has_widgets=True, has_webengine=True):
        """Return a list of context managers that mock the full detection stack."""
        def _find_spec(name):
            if name == "PyQt6.QtWidgets":
                return object() if has_widgets else None
            if name == "PyQt6.QtWebEngineWidgets":
                return object() if has_webengine else None
            return None

        patches = [
            patch("launch._display_available", return_value=display),
            patch("launch.importlib.util.find_spec", side_effect=_find_spec),
        ]
        # Patch the docker check inside _desktop_stack_available
        try:
            from megido_security import platform_utils
            patches.append(
                patch(
                    "megido_security.platform_utils.is_running_in_docker",
                    return_value=in_docker,
                )
            )
        except ImportError:
            pass
        return patches

    def _run(self, **kwargs):
        patches = self._patch_all(**kwargs)
        ctx = [p.__enter__() for p in patches]
        try:
            return launch._desktop_stack_available()
        finally:
            for p, c in zip(patches, ctx):
                p.__exit__(None, None, None)

    def test_all_available(self):
        assert self._run(display=True, in_docker=False, has_widgets=True, has_webengine=True) is True

    def test_no_display(self):
        assert self._run(display=False, in_docker=False, has_widgets=True, has_webengine=True) is False

    def test_in_docker(self):
        assert self._run(display=True, in_docker=True, has_widgets=True, has_webengine=True) is False

    def test_missing_widgets(self):
        assert self._run(display=True, in_docker=False, has_widgets=False, has_webengine=True) is False

    def test_missing_webengine(self):
        assert self._run(display=True, in_docker=False, has_widgets=True, has_webengine=False) is False


# ---------------------------------------------------------------------------
# _run_mode
# ---------------------------------------------------------------------------

class TestRunMode:
    """Mode selection decisions are tested without actually spawning subprocesses."""

    def setup_method(self):
        self.web_calls = []
        self.desktop_calls = []

        def fake_web(args):
            self.web_calls.append(args)
            return 0

        def fake_desktop(extra_args=None):
            self.desktop_calls.append(extra_args)
            return 0

        self._p_web = patch("launch._run_web", side_effect=fake_web)
        self._p_desk = patch("launch._run_desktop_browser", side_effect=fake_desktop)

    def _run(self, mode, desktop_ok=True, **kwargs):
        args = _args(**kwargs)
        with self._p_web, self._p_desk:
            with patch("launch._desktop_stack_available", return_value=desktop_ok):
                return launch._run_mode(mode, args)

    # explicit web mode always goes web
    def test_web_mode(self):
        self._run("web")
        assert len(self.web_calls) == 1
        assert len(self.desktop_calls) == 0

    # auto with full stack → desktop
    def test_auto_desktop_when_stack_available(self):
        self._run("auto", desktop_ok=True)
        assert len(self.desktop_calls) == 1
        assert len(self.web_calls) == 0

    # auto without stack → web
    def test_auto_web_when_stack_unavailable(self):
        self._run("auto", desktop_ok=False)
        assert len(self.web_calls) == 1
        assert len(self.desktop_calls) == 0

    # desktop with full stack → desktop
    def test_desktop_mode_stack_available(self):
        self._run("desktop", desktop_ok=True)
        assert len(self.desktop_calls) == 1
        assert len(self.web_calls) == 0

    # desktop-browser fallback to web when stack unavailable
    def test_desktop_browser_fallback_to_web(self, capsys):
        self._run("desktop-browser", desktop_ok=False)
        assert len(self.web_calls) == 1
        assert len(self.desktop_calls) == 0
        captured = capsys.readouterr()
        assert "falling back to web mode" in captured.out.lower()


# ---------------------------------------------------------------------------
# platform_utils helpers
# ---------------------------------------------------------------------------

class TestPlatformUtils:
    def test_desktop_stack_available_no_display(self):
        from megido_security import platform_utils
        with patch.object(platform_utils, "display_available", return_value=False):
            assert platform_utils.desktop_stack_available() is False

    def test_desktop_stack_available_in_docker(self):
        from megido_security import platform_utils
        with patch.object(platform_utils, "display_available", return_value=True):
            with patch.object(platform_utils, "is_running_in_docker", return_value=True):
                assert platform_utils.desktop_stack_available() is False

    def test_desktop_stack_available_missing_webengine(self):
        from megido_security import platform_utils
        orig_find = platform_utils.importlib.util.find_spec

        def fake_spec(name):
            if name == "PyQt6.QtWebEngineWidgets":
                return None
            return orig_find(name)

        with patch.object(platform_utils, "display_available", return_value=True):
            with patch.object(platform_utils, "is_running_in_docker", return_value=False):
                with patch.object(platform_utils.importlib.util, "find_spec", side_effect=fake_spec):
                    assert platform_utils.desktop_stack_available() is False

    def test_mitmdump_available_present(self):
        from megido_security import platform_utils
        with patch.object(platform_utils, "find_executable", return_value="/usr/bin/mitmdump"):
            assert platform_utils.mitmdump_available() is True

    def test_mitmdump_available_absent(self):
        from megido_security import platform_utils
        with patch.object(platform_utils, "find_executable", return_value=None):
            assert platform_utils.mitmdump_available() is False

    def test_display_available_linux_no_env(self):
        from megido_security import platform_utils
        with patch.object(platform_utils.platform, "system", return_value="Linux"):
            with patch.dict("os.environ", {}, clear=True):
                assert platform_utils.display_available() is False

    def test_display_available_linux_with_x11(self):
        from megido_security import platform_utils
        with patch.object(platform_utils.platform, "system", return_value="Linux"):
            with patch.dict("os.environ", {"DISPLAY": ":0"}, clear=True):
                assert platform_utils.display_available() is True

    def test_display_available_windows(self):
        from megido_security import platform_utils
        with patch.object(platform_utils.platform, "system", return_value="Windows"):
            assert platform_utils.display_available() is True
