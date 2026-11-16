import argparse


def main():
    ap = argparse.ArgumentParser(description="PhishGuard Mail Scanner")
    ap.add_argument("--server", action="store_true", help="Run the web UI server instead of the desktop GUI")
    ap.add_argument("--host", default="127.0.0.1", help="Web server host (with --server)")
    ap.add_argument("--port", type=int, default=8080, help="Web server port (with --server)")
    args, _ = ap.parse_known_args()
    if args.server:
        from server import main as server_main
        raise SystemExit(server_main(["--host", args.host, "--port", str(args.port)]))
    from gui import main as gui_main
    gui_main()


if __name__ == "__main__":
    main()

