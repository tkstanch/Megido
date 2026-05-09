#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON:-python3}"

cd "$SCRIPT_DIR"
exec "$PYTHON_BIN" launch.py desktop-browser "$@"
