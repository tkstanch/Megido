# Megido Distribution and Downloads

This document defines the current public distribution model for Megido.

## Officially Supported Download/Install Paths

1. **Docker** (recommended for most users)
2. **Source + setup scripts** (`setup.sh`, `setup.ps1`, `setup.bat`)
3. **GitHub Releases** (tagged source bundles)

Megido currently distributes **source-based bundles**, not fully packaged native installers.

## Canonical Launch Command

For local/script installs, launch Megido with:

```bash
python launch.py
```

Common modes:

- `python launch.py` (auto)
- `python launch.py web`
- `python launch.py desktop-browser`

## Release Automation

The release workflow (`.github/workflows/release-bundles.yml`) runs on pushed tags and publishes downloadable archives to GitHub Releases.

Current release assets are source bundles labeled by runner platform:

- `megido-<tag>-linux.tar.gz`
- `megido-<tag>-macos.tar.gz`
- `megido-<tag>-windows.zip`

These artifacts are intended to make download and setup easier while preserving the current architecture.

## What is not shipped yet

- Native signed installers (`.msi`, `.dmg`, distro packages)
- Standalone one-file binaries

Those can be evaluated later as a separate packaging phase.
