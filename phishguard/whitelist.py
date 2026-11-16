from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class Whitelist:
    exact: Dict[str, List[str]] = field(default_factory=dict)
    regex: Dict[str, List[str]] = field(default_factory=dict)
    trusted_domains_in_urls: List[str] = field(default_factory=list)
    trusted_domains_in_emails: List[str] = field(default_factory=list)
    _compiled: Dict[str, List[re.Pattern]] = field(default_factory=dict, init=False)

    def compile(self):
        self._compiled = {k: [] for k in ("domain", "url", "ip", "email")}
        for k in self._compiled:
            for pat in (self.regex.get(k) or []):
                try:
                    self._compiled[k].append(re.compile(pat, re.IGNORECASE))
                except re.error:
                    pass
        return self

    def _exact_hit(self, kind: str, value: str) -> bool:
        vals = {v.lower() for v in (self.exact.get(kind) or [])}
        return value.lower() in vals

    def _regex_hit(self, kind: str, value: str) -> bool:
        for rx in self._compiled.get(kind, []):
            if rx.search(value):
                return True
        return False

    def domain_trusted_for_url(self, host: str) -> bool:
        h = (host or "").lower().strip(".")
        for d in self.trusted_domains_in_urls:
            d = d.lower().strip(".")
            if h == d or h.endswith("." + d):
                return True
        return False

    def domain_trusted_for_email(self, domain: str) -> bool:
        d0 = (domain or "").lower().strip(".")
        for d in self.trusted_domains_in_emails:
            d = d.lower().strip(".")
            if d0 == d or d0.endswith("." + d):
                return True
        return False

    def is_whitelisted(self, kind: str, value: str) -> bool:
        v = (value or "").strip()
        if not v:
            return False
        if self._exact_hit(kind, v) or self._regex_hit(kind, v):
            return True
        if kind == "url":
            try:
                host = (urlparse(v).hostname or "").lower()
            except Exception:
                host = ""
            if host and self.domain_trusted_for_url(host):
                return True
        if kind == "email":
            if "@" in v:
                dom = v.rsplit("@", 1)[-1].lower()
                if self.domain_trusted_for_email(dom):
                    return True
        if kind == "domain":
            # treat domain as trusted for url/email contexts if listed
            if self.domain_trusted_for_url(v) or self.domain_trusted_for_email(v):
                return True
        return False


def load_whitelist(path: Optional[str]) -> Optional[Whitelist]:
    """Load whitelist from PhishGuard schema or ThePhish-compatible schema."""
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    # ThePhish schema compatibility (exactMatching/regexMatching/domainsIn*)
    if "exactMatching" in data or "regexMatching" in data or "domainsInURLs" in data or "domainsInEmails" in data:
        exact_m = data.get("exactMatching") or {}
        regex_m = data.get("regexMatching") or {}
        exact = {
            "domain": exact_m.get("domain") or [],
            "url": exact_m.get("url") or [],
            "ip": exact_m.get("ip") or [],
            "email": exact_m.get("mail") or exact_m.get("email") or [],
            "filename": exact_m.get("filename") or [],
            "hash": exact_m.get("hash") or [],
        }
        regex = {
            "domain": regex_m.get("domain") or [],
            "url": regex_m.get("url") or [],
            "ip": regex_m.get("ip") or [],
            "email": regex_m.get("mail") or regex_m.get("email") or [],
        }
        wl = Whitelist(
            exact=exact,
            regex=regex,
            trusted_domains_in_urls=(data.get("domainsInURLs") or []) + (data.get("domainsInSubdomains") or []),
            trusted_domains_in_emails=(data.get("domainsInEmails") or []),
        )
        return wl.compile()

    # PhishGuard schema
    wl = Whitelist(
        exact=data.get("exact") or {},
        regex=data.get("regex") or {},
        trusted_domains_in_urls=data.get("trusted_domains_in_urls") or [],
        trusted_domains_in_emails=data.get("trusted_domains_in_emails") or [],
    )
    return wl.compile()


class WhitelistError(ValueError):
    """Raised when a whitelist file cannot be read or updated safely."""


def _read_whitelist_json(path: Path) -> dict:
    if not path.is_file():
        raise WhitelistError(f"Whitelist file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise WhitelistError(f"Invalid whitelist JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise WhitelistError("Whitelist JSON must contain an object at the top level.")
    return data


def _schema_sections(data: dict):
    """Return (mode, exact_section, regex_section) for either supported schema."""
    if "exactMatching" in data or "regexMatching" in data or "domainsInURLs" in data or "domainsInEmails" in data:
        return "thephish", data.setdefault("exactMatching", {}), data.setdefault("regexMatching", {})
    return "phishguard", data.setdefault("exact", {}), data.setdefault("regex", {})


def whitelist_summary(path: Optional[str]) -> dict:
    """Return a small, safe summary of the whitelist at *path* (no matching side effects)."""
    result = {"path": str(path or ""), "exists": False, "schema": "", "exact": 0, "regex": 0, "trusted_url": 0, "trusted_email": 0, "error": ""}
    if not path:
        return result
    p = Path(path)
    result["exists"] = p.is_file()
    if not p.is_file():
        result["error"] = "file not found"
        return result
    try:
        data = _read_whitelist_json(p)
    except WhitelistError as exc:
        result["error"] = str(exc)
        return result
    mode, exact, regex = _schema_sections(data)
    result["schema"] = mode

    def _count(section, key):
        vals = section.get(key) if isinstance(section, dict) else None
        return len(vals) if isinstance(vals, list) else 0

    for key in ("domain", "url", "ip", "email", "mail", "filename", "hash"):
        result["exact"] += _count(exact, key)
        result["regex"] += _count(regex, key)
    result["trusted_url"] = len(data.get("trusted_domains_in_urls") or data.get("domainsInURLs") or [])
    result["trusted_email"] = len(data.get("trusted_domains_in_emails") or data.get("domainsInEmails") or [])
    if not load_whitelist(str(p)):
        result["error"] = "could not compile whitelist rules"
    return result


def validate_whitelist(path: Optional[str]) -> tuple[bool, str]:
    """Validate a whitelist file and return (ok, human-readable message)."""
    if not path:
        return False, "No whitelist path selected."
    info = whitelist_summary(path)
    if info["error"]:
        return False, f"Whitelist invalid: {info['error']}"
    return True, (
        f"Whitelist OK ({info['schema']} schema): {info['exact']} exact, {info['regex']} regex, "
        f"{info['trusted_url']} trusted URL domain(s), {info['trusted_email']} trusted email domain(s)."
    )


def add_exact_rule(path: Optional[str], kind: str, value: str) -> bool:
    """Add an exact-match whitelist rule, preserving the file's existing schema.

    Returns True when the rule was added, False when it already existed.
    Raises WhitelistError for invalid input or an unreadable existing file.
    """
    if not path:
        raise WhitelistError("No whitelist path selected.")
    kind = (kind or "").strip().lower()
    value = (value or "").strip()
    if kind not in ("domain", "url", "ip", "email", "filename", "hash"):
        raise WhitelistError(f"Unsupported whitelist rule type: {kind}")
    if not value:
        raise WhitelistError("Empty whitelist value.")
    p = Path(path)
    if p.is_file():
        data = _read_whitelist_json(p)
    else:
        data = {
            "exact": {"domain": [], "url": [], "ip": [], "email": [], "filename": [], "hash": []},
            "regex": {"domain": [], "url": [], "ip": [], "email": []},
            "trusted_domains_in_urls": [],
            "trusted_domains_in_emails": [],
        }
    _mode, exact, _regex = _schema_sections(data)
    if not isinstance(exact, dict):
        raise WhitelistError("Whitelist exact-match section must be an object.")
    key = "mail" if data.get("exactMatching") is not None and kind == "email" else kind
    rules = exact.get(key)
    if not isinstance(rules, list):
        rules = []
        exact[key] = rules
    if any(str(existing).strip().lower() == value.lower() for existing in rules):
        return False
    rules.append(value)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    return True
