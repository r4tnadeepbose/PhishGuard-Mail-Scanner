#!/usr/bin/env python3
"""PhishGuard Mail Scanner - local web server UI.

Run:
  python server.py
  python server.py --host 127.0.0.1 --port 8080

Serves a web UI and JSON API backed by the existing phishguard scanner.
Local/offline analysis only (no attachment execution, no URL browsing, no uploads).
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import re
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
WEB_DIR = ROOT / "web"
SAMPLES_DIR = ROOT / "samples"
DEFAULT_WHITELIST = ROOT / "whitelist.json"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phishguard.scanner import scan_email
from phishguard.investigation import scan_result_to_investigation
from phishguard.whitelist import validate_whitelist, whitelist_summary, add_exact_rule
from phishguard.report import result_to_json, result_to_html, results_batch_to_json, results_batch_to_html
from phishguard.threat_framework import calculate_cvss_v31_base


def _json(handler: BaseHTTPRequestHandler, status: int, payload):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


def _text(handler: BaseHTTPRequestHandler, status: int, content: str, content_type: str):
    data = (content or "").encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


def _read_json(handler: BaseHTTPRequestHandler):
    try:
        length = int(handler.headers.get("Content-Length", "0") or 0)
    except Exception:
        length = 0
    raw = handler.rfile.read(length) if length > 0 else b""
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _safe_sample_path(name: str) -> Path | None:
    if not name or "/" in name or "\\" in name or ".." in name:
        return None
    p = (SAMPLES_DIR / name).resolve()
    try:
        if SAMPLES_DIR.resolve() not in p.parents and p != SAMPLES_DIR.resolve():
            return None
    except Exception:
        return None
    if p.is_file() and p.suffix.lower() in {".eml", ".txt", ".mail"}:
        return p
    return None


def _scan_payload(body: dict):
    content = str(body.get("content") or "")
    if not content.strip():
        raise ValueError("No email content provided.")
    enable_ml = bool(body.get("enable_ml", True))
    whitelist_path = body.get("whitelist_path") or None
    use_default_whitelist = bool(body.get("use_default_whitelist", True))
    source = str(body.get("source") or "web")
    result = scan_email(
        content,
        whitelist_path=whitelist_path,
        use_default_whitelist=use_default_whitelist,
        enable_ml=enable_ml,
    )
    case = scan_result_to_investigation(result, raw_email_text=content, source=source)
    return content, result, case


def _defang(text: str) -> str:
    s = str(text or "")
    s = s.replace("http://", "hxxp://").replace("https://", "hxxps://")
    s = s.replace(".", "[.]").replace("@", "[@]").replace(":", "[:]")
    return s


def _refang(text: str) -> str:
    s = str(text or "")
    s = s.replace("hxxps://", "https://").replace("hxxp://", "http://")
    s = s.replace("[.]", ".").replace("[@]", "@").replace("[:]", ":")
    return s


class PhishGuardHandler(BaseHTTPRequestHandler):
    server_version = "PhishGuardServer/1.1"

    def log_message(self, fmt, *args):  # quieter
        sys.stderr.write("[web] " + (fmt % args) + "\n")

    def _serve_static(self, path: str):
        if path == "/":
            rel = "index.html"
        else:
            rel = path.lstrip("/")
        fs = (WEB_DIR / rel).resolve()
        try:
            if WEB_DIR.resolve() not in fs.parents and fs != WEB_DIR.resolve():
                return _json(self, 403, {"error": "Forbidden"})
        except Exception:
            return _json(self, 403, {"error": "Forbidden"})
        if not fs.is_file():
            return _json(self, 404, {"error": "Not found"})
        ctype, _ = mimetypes.guess_type(str(fs))
        data = fs.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        try:
            if path == "/api/health":
                return _json(self, 200, {"ok": True, "app": "PhishGuard Mail Scanner", "version": "1.1"})
            if path == "/api/samples":
                items = []
                if SAMPLES_DIR.is_dir():
                    for p in sorted(SAMPLES_DIR.iterdir()):
                        if p.is_file() and p.suffix.lower() in {".eml", ".txt", ".mail"}:
                            items.append({"name": p.name, "size": p.stat().st_size})
                return _json(self, 200, {"samples": items})
            if path == "/api/sample":
                name = (qs.get("name") or [""])[0]
                p = _safe_sample_path(name)
                if not p:
                    return _json(self, 404, {"error": "Sample not found"})
                content = p.read_text(encoding="utf-8", errors="replace")
                return _json(self, 200, {"name": p.name, "content": content})
            if path in ("/api/whitelist", "/api/whitelist/summary"):
                wpath = (qs.get("path") or [str(DEFAULT_WHITELIST)])[0]
                ok, msg = validate_whitelist(wpath)
                info = whitelist_summary(wpath) if ok else whitelist_summary(wpath)
                return _json(self, 200, {"path": wpath, "valid": ok, "message": msg, "summary": info})
            if path == "/api/config":
                return _json(self, 200, {
                    "default_whitelist": str(DEFAULT_WHITELIST),
                    "samples_dir": str(SAMPLES_DIR),
                    "features": ["scan", "batch", "export", "cvss", "whitelist", "defang", "samples", "history", "help", "hash", "base64", "ioc", "markdown", "rescan", "category_breakdown"]
                })
            if path.startswith("/api/"):
                return _json(self, 404, {"error": "Not found"})
            return self._serve_static(path)
        except Exception as e:
            traceback.print_exc()
            return _json(self, 500, {"error": str(e)})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/scan":
                body = _read_json(self)
                content, result, case = _scan_payload(body)
                payload = {"result": result.to_dict(), "case": case.to_dict()}
                # optional inline exports
                if body.get("include_export_json"):
                    payload["export_json"] = result_to_json(result)
                if body.get("include_export_html"):
                    payload["export_html"] = result_to_html(result)
                return _json(self, 200, payload)

            if path == "/api/scan/export":
                body = _read_json(self)
                content, result, case = _scan_payload(body)
                fmt = str(body.get("format") or "json").lower()
                if fmt == "html":
                    return _text(self, 200, result_to_html(result), "text/html; charset=utf-8")
                if fmt == "case":
                    return _json(self, 200, case.to_dict())
                return _text(self, 200, result_to_json(result), "application/json; charset=utf-8")

            if path == "/api/scan/batch":
                body = _read_json(self)
                items = body.get("items") or []
                if not isinstance(items, list) or not items:
                    return _json(self, 400, {"error": "No batch items provided."})
                enable_ml = bool(body.get("enable_ml", True))
                whitelist_path = body.get("whitelist_path") or None
                use_default_whitelist = bool(body.get("use_default_whitelist", True))
                results = []
                batch_dicts = []
                for idx, item in enumerate(items[:200]):  # safety cap
                    if not isinstance(item, dict):
                        item = {"content": str(item)}
                    name = str(item.get("name") or item.get("source") or f"item_{idx+1}")
                    content = str(item.get("content") or "")
                    try:
                        result = scan_email(content, whitelist_path=whitelist_path, use_default_whitelist=use_default_whitelist, enable_ml=enable_ml)
                        case = scan_result_to_investigation(result, raw_email_text=content, source=name)
                        rd = result.to_dict(); rd["source"] = name
                        results.append({"name": name, "result": rd, "case": case.to_dict(), "ok": True})
                        batch_dicts.append(rd)
                    except Exception as e:
                        results.append({"name": name, "ok": False, "error": str(e)})
                out = {"count": len(results), "results": results}
                if body.get("include_batch_report_json"):
                    out["batch_report_json"] = results_batch_to_json(batch_dicts)
                if body.get("include_batch_report_html"):
                    out["batch_report_html"] = results_batch_to_html(batch_dicts)
                return _json(self, 200, out)

            if path == "/api/samples/scan_all":
                body = _read_json(self)
                enable_ml = bool(body.get("enable_ml", True))
                whitelist_path = body.get("whitelist_path") or None
                use_default_whitelist = bool(body.get("use_default_whitelist", True))
                results = []
                batch_dicts = []
                files = []
                if SAMPLES_DIR.is_dir():
                    files = [p for p in sorted(SAMPLES_DIR.iterdir()) if p.is_file() and p.suffix.lower() in {".eml", ".txt", ".mail"}]
                for p in files:
                    content = p.read_text(encoding="utf-8", errors="replace")
                    try:
                        result = scan_email(content, whitelist_path=whitelist_path, use_default_whitelist=use_default_whitelist, enable_ml=enable_ml)
                        case = scan_result_to_investigation(result, raw_email_text=content, source=p.name)
                        rd = result.to_dict(); rd["source"] = p.name
                        results.append({"name": p.name, "result": rd, "case": case.to_dict(), "ok": True})
                        batch_dicts.append(rd)
                    except Exception as e:
                        results.append({"name": p.name, "ok": False, "error": str(e)})
                return _json(self, 200, {"count": len(results), "results": results})

            if path == "/api/validate_whitelist":
                body = _read_json(self)
                wpath = str(body.get("path") or DEFAULT_WHITELIST)
                ok, msg = validate_whitelist(wpath)
                info = whitelist_summary(wpath) if ok else None
                return _json(self, 200, {"valid": ok, "message": msg, "summary": info, "path": wpath})

            if path == "/api/whitelist/add":
                body = _read_json(self)
                wpath = str(body.get("path") or DEFAULT_WHITELIST)
                kind = str(body.get("kind") or "")
                value = str(body.get("value") or "")
                changed, msg = add_exact_rule(wpath, kind, value)
                ok, vmsg = validate_whitelist(wpath)
                info = whitelist_summary(wpath) if ok else None
                return _json(self, 200, {"ok": True, "changed": changed, "message": msg, "valid": ok, "validation": vmsg, "summary": info, "path": wpath})

            if path == "/api/cvss":
                body = _read_json(self)
                vector = str(body.get("vector") or "")
                if not vector.strip():
                    return _json(self, 400, {"error": "No CVSS vector provided."})
                try:
                    cvss = calculate_cvss_v31_base(vector)
                    return _json(self, 200, {"ok": True, "cvss": cvss})
                except Exception as e:
                    return _json(self, 400, {"ok": False, "error": str(e)})

            if path == "/api/defang":
                body = _read_json(self)
                text = str(body.get("text") or body.get("value") or "")
                mode = str(body.get("mode") or "defang").lower()
                out = _refang(text) if mode == "refang" else _defang(text)
                return _json(self, 200, {"ok": True, "mode": mode, "input": text, "output": out})

            return _json(self, 404, {"error": "Not found"})
        except ValueError as e:
            return _json(self, 400, {"error": str(e)})
        except Exception as e:
            traceback.print_exc()
            return _json(self, 500, {"error": str(e), "type": e.__class__.__name__})


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run PhishGuard web server")
    ap.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    args = ap.parse_args(argv)

    if not WEB_DIR.is_dir():
        print(f"ERROR: web UI directory not found: {WEB_DIR}", file=sys.stderr)
        return 2

    server = ThreadingHTTPServer((args.host, args.port), PhishGuardHandler)
    url = f"http://{args.host}:{args.port}/"
    print(f"PhishGuard web UI: {url}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
