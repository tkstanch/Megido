#!/usr/bin/env python3
"""Compatibility entrypoint that delegates to the unified launcher."""

from __future__ import annotations

import sys

import launch


if __name__ == "__main__":
    raise SystemExit(launch.main(["desktop-browser", *sys.argv[1:]]))
