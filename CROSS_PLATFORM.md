# Cross-Platform Notes

Megido now centralizes platform-specific behavior in `megido_security/platform_utils.py` and unified entrypoints:

- Setup: `python -m megido_security.setup`
- Launch: `python launch.py`
- Script wrappers (`setup.sh/.bat/.ps1`, `launch_megido_browser.sh/.bat`, `desktop_app.py`) all delegate to these Python entrypoints.

## Platform abstraction layer

`megido_security/platform_utils.py` provides:

- `get_config_dir()`, `get_data_dir()`, `get_cache_dir()`, `get_log_dir()` via `platformdirs`
- `open_in_browser(url)`
- `open_file(path)` with Windows/macOS/Linux fallbacks
- `is_admin()`
- `find_executable(name)`
- `display_available()` – True on Windows/macOS; True on Linux only when `DISPLAY` or `WAYLAND_DISPLAY` is set
- `desktop_stack_available()` – True when a display is present, not running in a container, and `PyQt6` + `PyQt6-WebEngine` are importable
- `mitmdump_available()` – True when `mitmdump` is on PATH

## Mode selection and fallback

`launch.py` selects the launch mode as follows:

| Requested mode | Desktop stack available? | Actual mode |
|---|---|---|
| `auto` (default) | Yes | Desktop browser |
| `auto` (default) | No | Web mode (automatic fallback) |
| `web` | — | Web mode |
| `desktop` / `desktop-browser` | Yes | Desktop browser |
| `desktop` / `desktop-browser` | No | Web mode + user-friendly message |

The desktop stack is considered available only when **all** of these are true:
1. A graphical display is reachable.
2. The process is not running inside a Docker/container.
3. Both `PyQt6` and `PyQt6-WebEngine` are importable.

If `mitmdump` is not found on PATH when `launch_megido_browser.py` runs, it automatically
falls back to `--no-proxy` mode rather than exiting with an error.

## Known limitations

- Desktop mode requires GUI dependencies (Qt) and is not intended for headless CI containers.
- Some optional security tooling may require extra native packages by platform.
- Docker still targets Linux containers (including Docker Desktop on macOS/Windows).

## Reporting platform bugs

When filing an issue, include:

1. OS + version (`Windows 11`, `macOS 14`, distro + version, BSD variant)
2. Python version (`python --version`)
3. Whether you used Docker/WSL/native
4. Exact command and full error output
