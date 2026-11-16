"""Security framework mappings and CVSS helpers (independent, local/offline).

This module adds evidence-linked MITRE ATT&CK and CWE context for phishing triage,
plus a CVSS v3.1 base-score calculator. It does not claim CVE identification for
arbitrary email content (CVEs are product-specific); CVE references are provided
only as an optional, user-supplied or informational field where applicable.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --- MITRE ATT&CK (Enterprise) technique references relevant to email phishing ---
MITRE_TECHNIQUES = {
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    "T1566.001": {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
    },
    "T1566.002": {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    "T1598": {
        "id": "T1598",
        "name": "Phishing for Information",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1598/",
    },
    "T1534": {
        "id": "T1534",
        "name": "Internal Spearphishing",
        "tactic": "Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T1534/",
    },
    "T1204.002": {
        "id": "T1204.002",
        "name": "Malicious File",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1204/002/",
    },
}

# --- CWE references (weakness patterns commonly abused/enabled in phishing scenarios) ---
CWE_REFERENCES = {
    "CWE-290": {
        "id": "CWE-290",
        "name": "Authentication Bypass by Spoofing",
        "url": "https://cwe.mitre.org/data/definitions/290.html",
    },
    "CWE-346": {
        "id": "CWE-346",
        "name": "Origin Validation Error",
        "url": "https://cwe.mitre.org/data/definitions/346.html",
    },
    "CWE-451": {
        "id": "CWE-451",
        "name": "User Interface (UI) Misrepresentation of Critical Information",
        "url": "https://cwe.mitre.org/data/definitions/451.html",
    },
    "CWE-601": {
        "id": "CWE-601",
        "name": "URL Redirection to Untrusted Site ('Open Redirect')",
        "url": "https://cwe.mitre.org/data/definitions/601.html",
    },
    "CWE-1390": {
        "id": "CWE-1390",
        "name": "Weak Authentication",
        "url": "https://cwe.mitre.org/data/definitions/1390.html",
    },
    "CWE-358": {
        "id": "CWE-358",
        "name": "Improperly Implemented Security Check for Standard",
        "url": "https://cwe.mitre.org/data/definitions/358.html",
    },
    "CWE-20": {
        "id": "CWE-20",
        "name": "Improper Input Validation",
        "url": "https://cwe.mitre.org/data/definitions/20.html",
    },
}


def _blob(findings: Iterable[Any]) -> str:
    parts = []
    for f in findings or []:
        if isinstance(f, dict):
            parts.append(str(f.get("title", "")))
            parts.append(str(f.get("detail", "")))
        else:
            parts.append(str(getattr(f, "title", "")))
            parts.append(str(getattr(f, "detail", "")))
    return " ".join(parts).lower()


def map_mitre_attack(verdict: str, findings: Iterable[Any], category_scores: Dict[str, int]) -> List[Dict[str, str]]:
    """Return evidence-linked MITRE ATT&CK techniques (best-effort)."""
    text = _blob(findings)
    cats = category_scores or {}
    picked: List[str] = ["T1566"]  # email phishing context baseline for triage
    if cats.get("url", 0) > 0 or any(k in text for k in ("url", "link", "http", "domain")):
        picked.append("T1566.002")
    if cats.get("attachment", 0) > 0 or any(k in text for k in ("attachment", "macro", "double-extension", "file type")):
        picked.append("T1566.001")
        picked.append("T1204.002")
    if cats.get("content", 0) > 0 and any(k in text for k in ("credential", "password", "verify", "login", "sensitive-info", "otp")):
        picked.append("T1598")
    # de-dup preserve order
    out = []
    seen = set()
    for tid in picked:
        if tid in seen or tid not in MITRE_TECHNIQUES:
            continue
        seen.add(tid)
        out.append(dict(MITRE_TECHNIQUES[tid]))
    return out


def map_cwe(verdict: str, findings: Iterable[Any], auth: Dict[str, Any]) -> List[Dict[str, str]]:
    """Return relevant CWE references (contextual, not a formal vulnerability finding)."""
    text = _blob(findings)
    auth = auth or {}
    picked: List[str] = []
    if any(k in text for k in ("impersonation", "spoof", "lookalike", "typosquat", "display-name", "sender")):
        picked.extend(["CWE-290", "CWE-451"])
    if any(k in text for k in ("reply-to", "return-path", "message-id", "origin", "domain mismatch")):
        picked.append("CWE-346")
    if any(k in text for k in ("url", "link", "punycode", "redirect", "deceptive", "@")):
        picked.append("CWE-601")
    if any(str(auth.get(k, "unknown")).lower() in ("fail", "softfail", "none", "temperror", "permerror") for k in ("spf", "dkim", "dmarc")):
        picked.append("CWE-1390")
        picked.append("CWE-358")
    if not picked:
        picked.append("CWE-20")
    out = []
    seen = set()
    for cid in picked:
        if cid in seen or cid not in CWE_REFERENCES:
            continue
        seen.add(cid)
        out.append(dict(CWE_REFERENCES[cid]))
    return out


# --- CVSS v3.1 base score calculator (offline) ---
_CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "N": {"N": 0.85, "L": 0.62, "H": 0.27},
        "L": {"N": 0.85, "L": 0.68, "H": 0.5},  # Scope Changed
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": "U", "C": "C"},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _round_up_1dp(num: float) -> float:
    return math.ceil(num * 10) / 10.0


def cvss_severity(score: float) -> str:
    if score <= 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def calculate_cvss_v31_base(vector_or_metrics: Any) -> Dict[str, Any]:
    """Calculate CVSS v3.1 base score from a vector string or metrics dict.

    Accepts 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N' or a dict with keys
    AV, AC, PR, UI, S, C, I, A.
    """
    if isinstance(vector_or_metrics, str):
        vector = vector_or_metrics.strip()
        parts = [p for p in vector.split("/") if p]
        metrics: Dict[str, str] = {}
        for p in parts:
            if p.startswith("CVSS:"):
                continue
            if ":" in p:
                k, v = p.split(":", 1)
                metrics[k.upper()] = v.upper()
    elif isinstance(vector_or_metrics, dict):
        metrics = {str(k).upper(): str(v).upper() for k, v in vector_or_metrics.items()}
        vector = None  # type: ignore
    else:
        raise ValueError("Provide a CVSS:3.1 vector string or metrics dictionary.")

    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    missing = [k for k in required if k not in metrics]
    if missing:
        raise ValueError(f"Missing CVSS metrics: {', '.join(missing)}")

    av = metrics["AV"]; ac = metrics["AC"]; pr = metrics["PR"]; ui = metrics["UI"]
    scope = metrics["S"]; c = metrics["C"]; i = metrics["I"]; a = metrics["A"]

    try:
        av_v = _CVSS_METRICS["AV"][av]
        ac_v = _CVSS_METRICS["AC"][ac]
        ui_v = _CVSS_METRICS["UI"][ui]
        c_v = _CVSS_METRICS["C"][c]
        i_v = _CVSS_METRICS["I"][i]
        a_v = _CVSS_METRICS["A"][a]
        scope_changed = scope == "C"
        pr_v = _CVSS_METRICS["PR"]["L" if scope_changed else "N"][pr]
    except KeyError as exc:
        raise ValueError(f"Invalid CVSS metric value: {exc}") from exc

    iss = 1 - (1 - c_v) * (1 - i_v) * (1 - a_v)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(max(iss - 0.02, 0), 15)
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av_v * ac_v * pr_v * ui_v

    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = _round_up_1dp(min(1.08 * (impact + exploitability), 10))
    else:
        base = _round_up_1dp(min(impact + exploitability, 10))

    if vector is None:
        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"
    elif not vector.upper().startswith("CVSS:3.1/"):
        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"

    return {
        "version": "3.1",
        "vector": vector,
        "base_score": float(base),
        "severity": cvss_severity(base),
        "metrics": {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": scope, "C": c, "I": i, "A": a},
        "impact_subscore": round(impact, 4),
        "exploitability_subscore": round(exploitability, 4),
    }


def estimate_triage_cvss(score: int, verdict: str, findings: Iterable[Any]) -> Dict[str, Any]:
    """Estimate a CVSS-like triage score from PhishGuard risk (not a software CVE score)."""
    s = max(0, min(100, int(score or 0)))
    # Map 0-100 phishing risk to a 0.0-10.0 base-like severity for prioritization.
    base = round(min(10.0, (s / 10.0)), 1)
    # Phishing emails are network-delivered, typically require user interaction.
    text = _blob(findings)
    has_cred = any(k in text for k in ("credential", "password", "login", "verify", "sensitive-info"))
    has_attach = any(k in text for k in ("attachment", "macro", "file type", "double-extension"))
    c = "H" if has_cred else ("L" if s >= 40 else "N")
    i = "H" if has_attach or s >= 70 else ("L" if s >= 40 else "N")
    a = "L" if has_attach else "N"
    vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:{c}/I:{i}/A:{a}"
    try:
        calc = calculate_cvss_v31_base(vector)
        # blend: use formula result but keep within risk-derived band for transparency
        base = round((calc["base_score"] + base) / 2.0, 1)
    except Exception:
        calc = {"vector": vector}
    return {
        "type": "triage_estimate",
        "version": "3.1",
        "vector": calc.get("vector", vector),
        "base_score": float(base),
        "severity": cvss_severity(base),
        "note": "Estimated triage severity derived from phishing indicators; not a confirmed software vulnerability CVSS.",
    }


def build_security_assessment(
    verdict: str,
    score: int,
    findings: Iterable[Any],
    auth: Optional[Dict[str, Any]] = None,
    category_scores: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    auth = auth or {}
    category_scores = category_scores or {}
    mitre = map_mitre_attack(verdict, findings, category_scores)
    cwes = map_cwe(verdict, findings, auth)
    cvss = estimate_triage_cvss(score, verdict, findings)
    return {
        "cvss_estimate": cvss,
        "mitre_attack": mitre,
        "cwe": cwes,
        "cve_references": [],
        "notes": [
            "MITRE ATT&CK and CWE mappings are evidence-linked heuristics for analyst context.",
            "CVEs are product/version-specific and are not auto-attributed from email content; use external vulnerability intelligence for affected products if relevant.",
        ],
    }