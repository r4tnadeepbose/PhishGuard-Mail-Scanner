#!/usr/bin/env python3
"""One-click launcher for PhishGuard web UI."""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _wait_for_port(host: str, port: int, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run PhishGuard web UI")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically")
    args = ap.parse_args(argv)

    url = f"http://{args.host}:{args.port}/"

    if not args.no_browser:
        def _open():
            # give the server a moment to bind
            if _wait_for_port(args.host, args.port, timeout=8.0):
                try:
                    webbrowser.open(url)
                except Exception:
                    pass
        threading.Thread(target=_open, daemon=True).start()

    from server import main as server_main
    return int(server_main(["--host", args.host, "--port", str(args.port)]) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
