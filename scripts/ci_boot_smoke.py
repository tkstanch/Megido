"""Cross-platform boot smoke test used by CI."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time


def main() -> int:
    env = os.environ.copy()
    proc = subprocess.Popen(
        [sys.executable, "manage.py", "runserver", "127.0.0.1:8765"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    ready = False
    try:
        for _ in range(30):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if sock.connect_ex(("127.0.0.1", 8765)) == 0:
                    ready = True
                    break
            time.sleep(1)
    finally:
        proc.terminate()
        proc.wait(timeout=20)

    if not ready:
        raise SystemExit("Server did not start")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
