from __future__ import annotations

import email
import re
from email import policy
from email.message import Message
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

MAX_PARSE_BYTES = 5 * 1024 * 1024  # 5 MB safety limit for files
MAX_INPUT_CHARS = 2_000_000  # safety limit for in-memory text parsing


@dataclass
class ParsedEmail:
    subject: str = ""
    sender: str = ""
    reply_to: str = ""
    to: str = ""
    date: str = ""
    message_id: str = ""
    return_path: str = ""
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    received: List[str] = field(default_factory=list)
    auth_results: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    raw: str = ""


def _get_body_and_attachments(msg: Message):
    parts = []
    attachments: List[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            disp_l = disp.lower()
            filename = part.get_filename()
            if filename:
                attachments.append(str(filename))
                if "attachment" in disp_l:
                    continue
            elif "attachment" in disp_l:
                name = "unnamed-attachment"
                m = re.search(r'filename="?([^";]+)"?', disp, re.IGNORECASE)
                if m:
                    name = m.group(1)
                attachments.append(name)
                continue
            if "attachment" in disp_l:
                continue
            if ctype == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    parts.append(payload.decode(charset, errors="replace"))
            elif ctype == "text/html" and not parts:
                try:
                    html = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    html = payload.decode(charset, errors="replace")
                text = re.sub(r"<[^>]+>", " ", html)
                parts.append(text)
    else:
        ctype = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            charset = msg.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace")
        if ctype == "text/html":
            content = re.sub(r"<[^>]+>", " ", str(content))
        parts.append(str(content))
    body = "\n".join(p for p in parts if p).strip()
    seen = set()
    uniq = []
    for a in attachments:
        k = str(a).lower()
        if k not in seen:
            seen.add(k)
            uniq.append(str(a))
    return body, uniq


def _extract_auth_results(headers: Dict[str, str], raw: str) -> List[str]:
    vals = []
    for k, v in headers.items():
        if k.lower() in ("authentication-results", "arc-authentication-results", "received-spf"):
            if v:
                vals.append(f"{k}: {v}")
    if not vals:
        for line in raw.splitlines():
            if line.lower().startswith(("authentication-results:", "arc-authentication-results:", "received-spf:")):
                vals.append(line.strip())
    seen = set()
    out = []
    for v in vals:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _parse_simple_headers(raw: str):
    lines = raw.splitlines()
    headers: Dict[str, str] = {}
    received = []
    body_start = 0
    i = 0
    while i < min(len(lines), 80):
        line = lines[i]
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip()
            if key and key.replace("-", "").isalpha() and len(key) <= 40:
                j = i + 1
                val = v.strip()
                while j < len(lines) and lines[j].startswith((" ", "\t")):
                    val += " " + lines[j].strip()
                    j += 1
                if key.lower() == "received":
                    received.append(val)
                else:
                    headers[key] = val
                i = j
                continue
        body_start = 0
        break
    else:
        body_start = 0
    body = "\n".join(lines[body_start:]).strip() if body_start else raw.strip()
    return headers, received, body


def parse_email_text(text: str, max_chars: int = MAX_INPUT_CHARS) -> ParsedEmail:
    raw = text or ""
    if len(raw) > max_chars:
        raise ValueError(f"Input too large to parse safely ({len(raw)} chars > {max_chars} chars limit).")
    # Heuristic: treat as RFC822 if it looks like headers
    if "\n" in raw and ":" in (raw.splitlines()[0] if raw.splitlines() else "") and any(
        line.lower().startswith(h) for h in ("from:", "subject:", "to:", "received:", "date:", "mime-version:", "return-path:")
        for line in raw.splitlines()[:12]
    ):
        try:
            msg = email.message_from_string(raw, policy=policy.default)
            headers = {k: str(v) for k, v in msg.items()}
            body, attachments = _get_body_and_attachments(msg)
            received = [str(v) for v in msg.get_all("Received", [])] if msg.get_all("Received") else []
            auth_results = _extract_auth_results(headers, raw)
            return ParsedEmail(
                subject=str(msg.get("Subject", "")),
                sender=str(msg.get("From", "")),
                reply_to=str(msg.get("Reply-To", "")),
                to=str(msg.get("To", "")),
                date=str(msg.get("Date", "")),
                message_id=str(msg.get("Message-ID", "")),
                return_path=str(msg.get("Return-Path", "")),
                body=body,
                headers=headers,
                received=received,
                auth_results=auth_results,
                attachments=attachments,
                raw=raw,
            )
        except Exception:
            pass
    headers, received, body = _parse_simple_headers(raw)
    auth_results = _extract_auth_results(headers, raw)
    attachments = []
    for k, v in headers.items():
        if k.lower() in ("content-disposition",) and "filename=" in v.lower():
            m = re.search(r'filename="?([^";]+)"?', v, re.IGNORECASE)
            if m:
                attachments.append(m.group(1))
    return ParsedEmail(
        subject=headers.get("Subject", ""),
        sender=headers.get("From", ""),
        reply_to=headers.get("Reply-To", ""),
        to=headers.get("To", ""),
        date=headers.get("Date", ""),
        message_id=headers.get("Message-ID", ""),
        return_path=headers.get("Return-Path", ""),
        body=body,
        headers=headers,
        received=received,
        auth_results=auth_results,
        attachments=attachments,
        raw=raw,
    )


def parse_email_file(path: str, max_bytes: int = MAX_PARSE_BYTES) -> ParsedEmail:
    p = Path(path)
    size = p.stat().st_size
    if size > max_bytes:
        raise ValueError(f"File too large to parse safely ({size} bytes > {max_bytes} bytes limit): {path}")
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    return parse_email_text(raw, max_chars=max(1, max_bytes))
