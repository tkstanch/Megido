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
