#!/usr/bin/env python3
"""Unified Megido launcher for web and desktop modes."""

from __future__ import annotations

import argparse
import importlib
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _display_available() -> bool:
    if platform.system() in {"Windows", "Darwin"}:
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _run(command: list[str], env: dict[str, str] | None = None) -> int:
    return subprocess.run(command, cwd=str(ROOT), env=env).returncode


def _run_web(args: argparse.Namespace) -> int:
    env = os.environ.copy()
    if args.use_sqlite:
        env["USE_SQLITE"] = "true"

    # Windows-friendly web server fallback for local runs.
    if platform.system() == "Windows" and _module_available("waitress"):
        return _run(
            [
                sys.executable,
                "-m",
                "waitress",
                "--listen",
                f"{args.host}:{args.port}",
                "megido_security.wsgi:application",
            ],
            env=env,
        )

    return _run(
        [sys.executable, "manage.py", "runserver", f"{args.host}:{args.port}"],
        env=env,
    )


def _run_desktop_browser(extra_args: list[str] | None = None) -> int:
    command = [sys.executable, "launch_megido_browser.py"]
    if extra_args:
        command.extend(extra_args)
    return _run(command)


def _run_mode(mode: str, args: argparse.Namespace, extra_args: list[str] | None = None) -> int:
    if mode == "web":
        return _run_web(args)

    if mode in {"desktop", "desktop-browser"}:
        if not _display_available():
            print("No display detected, falling back to web mode.")
            return _run_web(args)
        return _run_desktop_browser(extra_args)

    # auto
    if _display_available() and _module_available("PyQt6"):
        return _run_desktop_browser(extra_args)
    return _run_web(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Megido unified launcher")
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["auto", "web", "desktop", "desktop-browser"],
        default="auto",
        help="Launch mode",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Web host")
    parser.add_argument("--port", type=int, default=8000, help="Web port")
    parser.add_argument(
        "--no-sqlite",
        action="store_true",
        help="Do not force USE_SQLITE=true for local launch",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, passthrough = parser.parse_known_args(argv)

    # Preserve compatibility with old flags.
    if passthrough:
        if "--web" in passthrough or "-w" in passthrough:
            args.mode = "web"
        if "--desktop" in passthrough or "-d" in passthrough or "--cef" in passthrough:
            args.mode = "desktop-browser"
        passthrough = [arg for arg in passthrough if arg not in {"--web", "-w", "--desktop", "-d", "--cef"}]

    args.use_sqlite = not args.no_sqlite
    return _run_mode(args.mode, args, passthrough)


if __name__ == "__main__":
    raise SystemExit(main())
