"""Unified cross-platform setup entrypoint for Megido."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(command: list[str], env: dict[str, str] | None = None) -> int:
    return subprocess.run(command, cwd=str(ROOT), env=env).returncode


def _venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _ensure_venv(venv_dir: Path) -> Path:
    venv_python = _venv_python(venv_dir)
    if venv_python.exists():
        return venv_python
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], cwd=str(ROOT), check=True)
    return _venv_python(venv_dir)


def _prompt_yes_no(prompt: str, default_yes: bool = True, non_interactive: bool = False) -> bool:
    if non_interactive:
        return default_yes
    default = "Y/n" if default_yes else "y/N"
    answer = input(f"{prompt} [{default}]: ").strip().lower()
    if not answer:
        return default_yes
    return answer in {"y", "yes"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Megido setup")
    parser.add_argument("--non-interactive", action="store_true", help="Disable prompts")
    parser.add_argument("--with-docker", action="store_true", help="Run with docker compose")
    parser.add_argument("--skip-docker", action="store_true", help="Skip docker prompt/path")
    parser.add_argument("--venv", default=".venv", help="Virtual environment directory")
    parser.add_argument("--no-venv", action="store_true", help="Install into current Python environment")
    parser.add_argument("--skip-npm", action="store_true", help="Skip npm install")
    parser.add_argument("--skip-playwright", action="store_true", help="Skip playwright install")
    parser.add_argument("--skip-collectstatic", action="store_true", help="Skip collectstatic")
    parser.add_argument("--runserver", action="store_true", help="Start server after setup")
    args = parser.parse_args(argv)

    use_docker = args.with_docker
    if not args.skip_docker and not args.with_docker:
        use_docker = _prompt_yes_no(
            "Do you want to use Docker (recommended)?",
            default_yes=True,
            non_interactive=args.non_interactive,
        )

    if use_docker:
        if shutil.which("docker") is None:
            print("Docker is not installed or not in PATH.")
            return 1
        return _run(["docker", "compose", "up", "--build"])

    if args.no_venv:
        venv_python = Path(sys.executable)
    else:
        venv_dir = ROOT / args.venv
        venv_python = _ensure_venv(venv_dir)

    if _run([str(venv_python), "-m", "pip", "install", "--upgrade", "pip"]) != 0:
        return 1
    if _run([str(venv_python), "-m", "pip", "install", "-r", "requirements.txt"]) != 0:
        return 1

    if (ROOT / "package.json").exists() and not args.skip_npm:
        if shutil.which("npm"):
            if _run(["npm", "install"]) != 0:
                return 1

    env = os.environ.copy()
    env["USE_SQLITE"] = "true"

    if _run([str(venv_python), "manage.py", "migrate", "--noinput"], env=env) != 0:
        return 1

    if not args.skip_collectstatic:
        if _run([str(venv_python), "manage.py", "collectstatic", "--noinput"], env=env) != 0:
            return 1

    if not args.skip_playwright:
        _run([str(venv_python), "-m", "playwright", "install"])

    if args.runserver:
        return _run([str(venv_python), "manage.py", "runserver"], env=env)

    print("Setup complete. Activate the environment and run: python launch.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
