from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .parser import ParsedEmail, parse_email_text, parse_email_file
from .whitelist import Whitelist, load_whitelist
from .ml_model import analyze_text_ml
from .threat_framework import build_security_assessment


@dataclass
class Finding:
    severity: str  # Low, Medium, High
    title: str
    detail: str
    score: int
    evidence: str = ""
    reasoning: str = ""
    recommended_action: str = ""


@dataclass
class ScanResult:
    verdict: str
    score: int
    findings: List[Finding] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    summary: str = ""
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    auth_analysis: Dict[str, Any] = field(default_factory=dict)
    observables: Dict[str, Any] = field(default_factory=dict)
    whitelist_applied: bool = False
    ml_analysis: Dict[str, Any] = field(default_factory=dict)
    category_scores: Dict[str, int] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    security_assessment: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "summary": self.summary,
            "source": self.source,
            "urls": self.urls,
            "findings": [asdict(f) for f in self.findings],
            "metadata": self.metadata,
            "auth_analysis": self.auth_analysis,
            "observables": self.observables,
            "whitelist_applied": self.whitelist_applied,
            "ml_analysis": self.ml_analysis,
            "category_scores": self.category_scores,
            "recommendations": self.recommendations,
            "security_assessment": self.security_assessment,
        }


SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "country", "stream", "gq", "tk", "ml", "cf", "ga",
    "work", "support", "fit", "rest", "cam",
}
URGENCY_PATTERNS = [
    r"urgent", r"immediately", r"within \d+ (?:hours|minutes|days)", r"act now", r"final warning",
    r"account (?:will be|has been) (?:suspended|locked|closed|limited)", r"verify (?:now|immediately)",
    r"unusual (?:activity|sign[- ]in)", r"action required", r"failure to (?:comply|respond)",
]
CREDENTIAL_PATTERNS = [
    r"\bpassword\b", r"\blogin\b", r"\blog in\b", r"\bsign in\b", r"verify your (?:account|identity|information)",
    r"confirm your (?:account|identity|details)", r"update your (?:payment|billing|account)",
    r"\bone[- ]time\b", r"\botp\b", r"security code", r"\bssn\b", r"bank details",
]
PAYMENT_PATTERNS = [
    r"wire transfer", r"gift card", r"bitcoin", r"crypto", r"invoice attached", r"payment overdue",
    r"refund", r"prize", r"won", r"lottery",
]
URGENCY_RE = [re.compile(p, re.IGNORECASE) for p in URGENCY_PATTERNS]
CREDENTIAL_RE = [re.compile(p, re.IGNORECASE) for p in CREDENTIAL_PATTERNS]
PAYMENT_RE = [re.compile(p, re.IGNORECASE) for p in PAYMENT_PATTERNS]
RISKY_ATTACH_HINTS = [".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".img", ".html", ".htm", ".lnk", ".zip", "macro", "enable content"]
RISKY_ATTACH_EXTS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".img", ".html", ".htm", ".lnk"}

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
DEFANGED_URL_RE = re.compile(r"(?:hxxps?|https?|ftp)://[^\s\"'<>)\]]+|(?:hxxps?|https?)\s*\[:\]\s*//[^\s\"'<>)\]]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}\b")
DANGEROUS_SCHEMES = ("javascript:", "data:", "file:", "vbscript:")
ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]")
BRAND_DOMAINS = {
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com", "hotmail.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "youtube.com"],
    "apple": ["apple.com", "icloud.com", "me.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in", "aws.amazon.com"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "linkedin": ["linkedin.com"],
    "netflix": ["netflix.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "bankofamerica": ["bankofamerica.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
}
FREEMAIL_DOMAINS = {"gmail.com","googlemail.com","outlook.com","hotmail.com","live.com","yahoo.com","yahoo.co.in","aol.com","icloud.com","proton.me","protonmail.com","gmx.com","zoho.com"}


def _normalize_obfuscated_text(text: str) -> str:
    t = text or ""
    # de-defang common forms
    t = t.replace("hxxps://", "https://").replace("hxxp://", "http://")
    t = t.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    t = t.replace("[:]", ":").replace("[://]", "://")
    t = re.sub(r"\b(hxxps?)\s*\[\:\]\s*//", lambda m: ("https://" if "s" in m.group(1).lower() else "http://"), t, flags=re.IGNORECASE)
    # decode common HTML entities minimally
    t = t.replace("&amp;", "&").replace("&#64;", "@").replace("&#46;", ".").replace("&#58;", ":")
    return t


def _levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if not a: return len(b)
    if not b: return len(a)
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins = cur[j-1] + 1
            dele = prev[j] + 1
            sub = prev[j-1] + (ca != cb)
            cur.append(min(ins, dele, sub))
        prev = cur
    return prev[-1]


def _confusable_skeleton(s: str) -> str:
    # lightweight confusable normalization for common lookalikes
    table = str.maketrans({
        "0":"o","1":"l","3":"e","5":"s","7":"t","@":"a","$":"s","!":"i",
        "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","і":"i", # cyrillic
    })
    return (s or "").lower().translate(table)


def _has_suspicious_unicode(s: str) -> bool:
    if not s: return False
    if ZERO_WIDTH_RE.search(s): return True
    # mixed non-ascii letters with ascii in domain-like tokens can be suspicious
    try:
        if any(ord(ch) > 127 for ch in s):
            cats = set()
            for ch in s:
                if ch.isalpha() and ord(ch) > 127:
                    # crude script buckets
                    o = ord(ch)
                    if 0x0400 <= o <= 0x04FF: cats.add("cyrillic")
                    elif 0x0370 <= o <= 0x03FF: cats.add("greek")
                    else: cats.add("other")
            return bool(cats)
    except Exception:
        return False
    return False


def extract_urls(text: str) -> List[str]:
    raw = text or ""
    norm = _normalize_obfuscated_text(raw)
    candidates = URL_RE.findall(raw) + URL_RE.findall(norm) + DEFANGED_URL_RE.findall(norm)
    cleaned = []
    for u in candidates:
        u = _normalize_obfuscated_text(u).strip().strip('"\'>)]},.;:!?')
        # normalize defanged spacing artifacts
        u = re.sub(r"\s+", "", u)
        if u.lower().startswith(("hxxp://", "hxxps://")):
            u = "http" + u[4:]
        if u:
            cleaned.append(u.rstrip(".,;:!?"))
    seen = set()
    out = []
    for u in cleaned:
        k = u.lower()
        if k not in seen:
            seen.add(k)
            out.append(u)
    return out


def extract_emails(text: str) -> List[str]:
    found = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text or "")
    seen = set(); out=[]
    for e in found:
        el=e.lower().strip(".,;:!?")
        if el not in seen:
            seen.add(el); out.append(el)
    return out


def extract_ips(text: str) -> List[str]:
    found = IP_RE.findall(text or "")
    seen = set(); out=[]
    for i in found:
        if i not in seen:
            seen.add(i); out.append(i)
    return out


def extract_domains(text: str, urls: List[str], emails: List[str]) -> List[str]:
    candidates = DOMAIN_RE.findall(text or "")
    url_hosts = set()
    for u in urls:
        try:
            h = (urlparse(u).hostname or "").lower()
            if h: url_hosts.add(h)
        except Exception:
            pass
    email_domains = set(e.rsplit('@',1)[-1].lower() for e in emails if '@' in e)
    seen = set(); out=[]
    for d in candidates:
        dl = d.lower().strip('.')
        if dl in seen: continue
        if dl in url_hosts or dl in email_domains:
            # already represented as url/email observable context; still include as domain too? include unique
            pass
        # skip common false positives like file extensions tokens in simple text
        if dl.split('.')[-1] in ('eml','txt','png','jpg','jpeg','pdf','docx','zip'):
            continue
        seen.add(dl); out.append(dl)
    return out


def _default_whitelist_path() -> Optional[str]:
    # project root / whitelist.json
    p = Path(__file__).resolve().parent.parent / "whitelist.json"
    return str(p) if p.is_file() else None


def extract_observables(text: str, whitelist: Optional[Whitelist] = None):
    norm = _normalize_obfuscated_text(text or "")
    urls = extract_urls(text)
    emails = extract_emails(norm)
    ips = extract_ips(norm)
    domains = extract_domains(norm, urls, emails)
    filtered = {"urls": [], "emails": [], "ips": [], "domains": [], "whitelisted": {"urls": [], "emails": [], "ips": [], "domains": []}}
    mapping = [("url", urls, "urls"), ("email", emails, "emails"), ("ip", ips, "ips"), ("domain", domains, "domains")]
    for kind, items, key in mapping:
        for item in items:
            if whitelist and whitelist.is_whitelisted(kind, item):
                filtered["whitelisted"][key].append(item)
            else:
                filtered[key].append(item)
    return filtered, urls  # raw urls for existing logic; but we will use filtered urls for scoring context where needed


def domain_from_addr(addr: str) -> str:
    m = EMAIL_RE.search(addr or "")
    return (m.group(1).lower() if m else "").strip()


def _score_to_verdict(score: int) -> str:
    s = max(0, min(100, int(score)))
    if s >= 70:
        return "Critical"
    if s >= 40:
        return "High Risk"
    if s >= 20:
        return "Suspicious"
    return "Low Risk"


def _finding_text(item: Any) -> str:
    """Return a lowercase text blob for a Finding or a finding dictionary."""
    if isinstance(item, dict):
        return f"{item.get('title', '')} {item.get('detail', '')}".lower()
    return f"{getattr(item, 'title', '')} {getattr(item, 'detail', '')}".lower()


def build_recommendations(verdict: str, findings: Optional[List[Any]], auth: Optional[Dict[str, Any]]) -> List[str]:
    """Build context-aware, de-duplicated recommended actions from a scan result."""
    findings = findings or []
    auth = auth or {}
    recs: List[str] = []
    v = (verdict or "").lower()
    if "critical" in v or "high" in v:
        recs.append("Do not click links, open attachments, or reply. Report this message to your security/IT team or email provider.")
    elif "suspicious" in v:
        recs.append("Treat with caution. Verify the sender and any requests via a trusted, independent channel before taking action.")
    else:
        recs.append("No strong phishing indicators detected, but remain cautious with unexpected links, attachments, or requests for sensitive information.")
    if auth and any(str(auth.get(k, "unknown")).lower() in ("fail", "softfail", "temperror", "permerror") for k in ("spf", "dkim", "dmarc")):
        recs.append("Authentication headers indicate failures (unverified header claims); treat sender identity with extra skepticism.")
    blobs = [_finding_text(f) for f in findings]
    if any("credential" in b or "password" in b for b in blobs):
        recs.append("Never enter passwords, OTPs, or recovery codes from an email link; navigate to the official site/app directly.")
    if any("attachment" in b or "macro" in b for b in blobs):
        recs.append("Do not open unexpected or risky attachments; scan with trusted security tools if business-critical.")
    if any("url" in b or "link" in b for b in blobs):
        recs.append("Inspect link destinations without clicking (hover/status bar) and prefer typed or bookmarked official addresses.")
    # de-dup while preserving order
    out: List[str] = []
    seen = set()
    for r in recs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out[:6]


def _finding_category(finding: Finding) -> str:
    """Map a finding to a stable reporting category (best-effort, deterministic)."""
    t = (finding.title + " " + finding.detail).lower()
    if any(k in t for k in ("spf", "dkim", "dmarc", "authentication-")):
        return "authentication"
    if any(k in t for k in ("attachment", "macro", "double-extension", "file type", "filename")):
        return "attachment"
    if any(k in t for k in ("url", "link", "domain", "tld", "punycode", "http", "ip address", "scheme", "observables")):
        return "url"
    if any(k in t for k in ("urgency", "credential", "payment", "lure", "greeting", "prize", "sensitive-info")):
        return "content"
    if any(k in t for k in ("reply-to", "return-path", "sender", "display-name", "received", "message-id", "header", "subject")):
        return "header_identity"
    return "other"


def _analyze_auth(parsed: ParsedEmail):
    findings: List[Finding] = []
    score = 0
    details = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "sources": parsed.auth_results}
    blob = "\n".join(parsed.auth_results).lower()

    def check(mech: str):
        # look for spf=pass/fail/softfail/neutral/none etc.
        m = re.search(rf"\b{mech}\s*=\s*([a-z0-9_-]+)", blob)
        return m.group(1) if m else None

    spf = check("spf")
    dkim = check("dkim")
    dmarc = check("dmarc")
    if spf: details["spf"] = spf
    if dkim: details["dkim"] = dkim
    if dmarc: details["dmarc"] = dmarc

    if not parsed.auth_results:
        # only a weak signal; absence can be normal in raw pasted text
        pass
    else:
        for mech, val in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)):
            if val in ("fail", "softfail", "temperror", "permerror"):
                sev = "High" if val == "fail" else "Medium"
                pts = 10 if val == "fail" else 6
                findings.append(Finding(
                    sev, f"{mech} check did not pass (header claim)",
                    f"Authentication result header indicates {mech.lower()}={val}.",
                    pts,
                    evidence=f"{mech.lower()}={val}",
                    reasoning="Header-reported authentication failures can indicate spoofing, but may also result from forwarding/misconfiguration; headers themselves are not independently verified here.",
                    recommended_action="Correlate with trusted mail infrastructure logs and other spoofing indicators before concluding."
                ))
                score += pts
            elif val == "none":
                findings.append(Finding(
                    "Low", f"{mech} result is none (header claim)",
                    f"Authentication result header indicates {mech.lower()}=none; sender domain may lack alignment/configuration.",
                    1,
                    evidence=f"{mech.lower()}=none",
                    reasoning="A 'none' result is weak evidence and common in some setups; it is not proof of phishing.",
                    recommended_action="Use as context only; prioritize stronger indicators."
                ))
                score += 1

        # generic received-spf fail
        for ar in parsed.auth_results:
            if ar.lower().startswith("received-spf:") and re.search(r"\b(fail|softfail)\b", ar.lower()):
                if not any("SPF check did not pass" in f.title for f in findings):
                    findings.append(Finding(
                        "High", "SPF check did not pass (header claim)",
                        f"Header: {ar}",
                        10,
                        evidence=ar,
                        reasoning="Received-SPF header suggests SPF failure but is a header claim not independently verified by this tool.",
                        recommended_action="Correlate with trusted gateway results and other indicators."
                    ))
                    score += 10

    return findings, score, details


def analyze_parsed(
    parsed: ParsedEmail,
    whitelist: Optional[Whitelist] = None,
    enable_ml: bool = True,
    whitelist_path: Optional[str] = None,
) -> ScanResult:
    findings: List[Finding] = []
    score = 0
    combined = "\n".join([parsed.subject, parsed.sender, parsed.reply_to, parsed.to, parsed.return_path, parsed.body])
    combined_lower = combined.lower()
    observables, all_urls = extract_observables(combined, whitelist)
    urls = observables.get("urls", [])  # scoring focuses on non-whitelisted URLs
    from_domain = domain_from_addr(parsed.sender)
    reply_domain = domain_from_addr(parsed.reply_to)

    def _domains_related(a: str, b: str) -> bool:
        a = (a or "").lower().strip(".")
        b = (b or "").lower().strip(".")
        if not a or not b:
            return False
        return a == b or a.endswith("." + b) or b.endswith("." + a)

    # Sender / header checks
    if parsed.reply_to and from_domain and reply_domain and not _domains_related(from_domain, reply_domain):
        findings.append(Finding("High", "Reply-To domain mismatch", f"From domain '{from_domain}' differs from Reply-To domain '{reply_domain}'.", 12))
        score += 12

    if parsed.sender and "@" not in parsed.sender:
        findings.append(Finding("Medium", "Unusual sender format", "From header does not contain a clear email address.", 6))
        score += 6

    # Display-name spoofing hint: name contains brand-like words but domain appears unrelated
    disp_match = re.match(r"\s*\"?([^\"<]+)\"?\s*<", parsed.sender or "")
    if disp_match and from_domain:
        disp = disp_match.group(1).lower()
        brand_domains = {
            "microsoft": ["microsoft.com", "outlook.com", "hotmail.com", "live.com"],
            "paypal": ["paypal.com"],
            "apple": ["apple.com", "icloud.com"],
            "google": ["google.com", "gmail.com"],
            "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
        }
        for brand, legit in brand_domains.items():
            if brand in disp:
                if not any(from_domain == d or from_domain.endswith('.' + d) for d in legit):
                    findings.append(Finding(
                        "Medium", "Possible display-name impersonation",
                        f"Display name '{disp_match.group(1).strip()}' references '{brand}' but sender domain is '{from_domain}'.",
                        8,
                        evidence=parsed.sender,
                        reasoning="Brand names in display names can be abused to impersonate trusted organizations when the sender domain is unrelated.",
                        recommended_action="Verify the sender via official channels and inspect the actual From address/domain."
                    ))
                    score += 8
                break

    if not parsed.sender and not parsed.headers:
        findings.append(Finding("Low", "Limited header information", "No sender/header metadata provided; analysis is based on body text only.", 2))
        score += 2

    # Return-Path mismatch (common in spoofing, but can be legitimate for mailing lists/services)
    rp_domain = domain_from_addr(parsed.return_path)
    if rp_domain and from_domain and not _domains_related(rp_domain, from_domain):
        # reduce noise if same registered-like second-level not easily known; keep moderate
        findings.append(Finding(
            "Medium", "Return-Path domain mismatch",
            f"Return-Path domain '{rp_domain}' differs from From domain '{from_domain}'.",
            5,
            evidence=parsed.return_path,
            reasoning="Envelope sender and visible From domain differ; this can occur in legitimate forwarding/services but is also common in spoofing.",
            recommended_action="Check alignment with SPF/DMARC context and sender legitimacy."
        ))
        score += 5
    elif rp_domain and from_domain and rp_domain != from_domain and _domains_related(rp_domain, from_domain):
        findings.append(Finding(
            "Low", "Return-Path uses related domain",
            f"Return-Path domain '{rp_domain}' differs from From domain '{from_domain}' but appears organizationally related.",
            1,
            evidence=parsed.return_path,
            reasoning="Related subdomain/envelope domains are common for legitimate bulk/transactional mail.",
            recommended_action="Usually benign when authentication passes and sender is expected; verify if unexpected."
        ))
        score += 1

    # Received hops analysis
    if parsed.received:
        if len(parsed.received) >= 8:
            findings.append(Finding("Low", "Many mail hops", f"Message passed through {len(parsed.received)} Received hops, which can warrant closer inspection.", 2, reasoning="Long chains can indicate forwarding or complex routing; not inherently malicious.", recommended_action="Review Received headers if investigating delivery path."))
            score += 2
    # Missing Received headers in pasted/header-only snippets is common; avoid scoring noise.

    # Advanced header/identity forensics (hardened checks)
    msgid = (parsed.message_id or "").strip()
    msgid_domain = domain_from_addr(msgid) if "@" in msgid else ""
    if from_domain and msgid_domain and not _domains_related(from_domain, msgid_domain):
        findings.append(Finding("Medium", "Message-ID domain mismatch", f"From domain '{from_domain}' differs from Message-ID domain '{msgid_domain}'.", 4,
                                evidence=parsed.message_id, reasoning="Legitimate mail usually has Message-ID generated by a related sending system, though exceptions exist (forwarders/lists).",
                                recommended_action="Correlate with other header/auth indicators before concluding."))
        score += 4
    if parsed.sender and _has_suspicious_unicode(parsed.sender):
        findings.append(Finding("High", "Suspicious Unicode in sender/display name", "Sender or display name contains non-ASCII/confusable characters.", 8,
                                evidence=parsed.sender, reasoning="Unicode/confusable characters can be used to spoof trusted identities.",
                                recommended_action="Inspect the exact From address and domain characters."))
        score += 8
    if from_domain in FREEMAIL_DOMAINS:
        disp = ""
        mdisp = re.match(r"\s*\"?([^\"<]+)\"?\s*<", parsed.sender or "")
        if mdisp:
            disp = mdisp.group(1).lower()
        org_terms = ("support", "security", "billing", "invoice", "service", "admin", "helpdesk", "bank", "paypal", "microsoft", "apple", "google", "amazon")
        if any(t in disp for t in org_terms):
            findings.append(Finding("Medium", "Freemail account claiming organization role", f"Sender uses freemail domain '{from_domain}' but display name suggests an organization/service role.", 6,
                                    evidence=parsed.sender, reasoning="Attackers often use freemail accounts while impersonating companies or support teams.",
                                    recommended_action="Verify through official channels; do not trust display names alone."))
            score += 6
    # Lookalike sender domain vs known brands
    if from_domain:
        sk = _confusable_skeleton(from_domain)
        for brand, legit_domains in BRAND_DOMAINS.items():
            if sk in legit_domains or any(sk.endswith('.'+d) for d in legit_domains):
                continue
            dist = _levenshtein(sk, brand + ".com")
            if 0 < dist <= 2 and len(sk) >= 6:
                findings.append(Finding("High", "Possible lookalike sender domain", f"Sender domain '{from_domain}' is very similar to '{brand}.com'.", 10,
                                        evidence=parsed.sender, reasoning="Typosquatting/lookalike sender domains are commonly used in targeted phishing.",
                                        recommended_action="Verify sender domain spelling carefully and contact the organization via known-good channels."))
                score += 10
                break
    # Hidden/evasion characters in raw content
    if ZERO_WIDTH_RE.search(parsed.raw or combined):
        findings.append(Finding("Medium", "Hidden/invisible characters detected", "Message contains zero-width or bidirectional-control characters that can be used to evade filters or obscure content.", 5,
                                reasoning="Invisible Unicode characters may be legitimate in some contexts but are also used in obfuscation.",
                                recommended_action="Inspect raw/source content and suspicious text segments carefully."))
        score += 5
    if re.search(r"(?is)<(script|form|iframe|base|meta)\b", parsed.raw or "") or re.search(r"(?is)display\s*:\s*none|font-size\s*:\s*0|opacity\s*:\s*0", parsed.raw or ""):
        findings.append(Finding("Medium", "HTML active/hidden-content indicators", "Raw message includes script/form/iframe/meta tags or hidden-CSS patterns.", 6,
                                reasoning="HTML tricks can hide malicious content, auto-redirect, or phish credentials.",
                                recommended_action="Treat embedded HTML with caution; avoid interacting with rendered active content."))
        score += 6
    if len((parsed.subject or "").strip()) == 0 and (parsed.body or parsed.headers):
        findings.append(Finding("Low", "Empty subject", "Message has no subject line, which can be used to appear informal or evade filters.", 1))
        score += 1

    # Attachment filename checks (metadata)
    for name in parsed.attachments:
        if whitelist and whitelist.is_whitelisted("filename", name):
            continue
        lower = name.lower()
        ext = ""
        if "." in lower:
            ext = "." + lower.rsplit(".", 1)[-1]
        if ext in RISKY_ATTACH_EXTS:
            findings.append(Finding("High", "Risky attachment type", f"Attachment '{name}' has a potentially dangerous file type ({ext}).", 10))
            score += 10
        if lower.count(".") >= 2:
            findings.append(Finding("Medium", "Double-extension filename", f"Attachment '{name}' uses multiple extensions, which can disguise executable content.", 6))
            score += 6

    # Authentication-Results / SPF / DKIM / DMARC (header claims - not independently verified)
    auth_findings, auth_score, auth_details = _analyze_auth(parsed)
    if parsed.auth_results:
        findings.append(Finding(
            "Low", "Authentication headers are unverified claims",
            "SPF/DKIM/DMARC values are parsed from message headers (e.g. Authentication-Results/Received-SPF) and are not cryptographically or externally verified by this tool.",
            0,
            evidence="; ".join(parsed.auth_results[:2]),
            reasoning="Authentication headers can be informative but may be forged or misinterpreted outside the receiving mail infrastructure.",
            recommended_action="Treat header-reported auth results as hints; verify with trusted mail gateway/server-side logs when possible."
        ))
    findings.extend(auth_findings)
    score += auth_score

    # Content checks (precompiled for speed)
    def any_match_compiled(regexes) -> List[str]:
        hits = []
        for rx in regexes:
            if rx.search(combined_lower):
                hits.append(rx.pattern)
        return hits

    urg = any_match_compiled(URGENCY_RE)
    if urg:
        findings.append(Finding("Medium", "Urgency/pressure language", "Message uses urgency or fear-based pressure tactics.", 8))
        score += 8
    cred = any_match_compiled(CREDENTIAL_RE)
    if cred:
        findings.append(Finding("High", "Credential or sensitive-info request", "Message appears to request login, verification, or sensitive information.", 12))
        score += 12
    pay = any_match_compiled(PAYMENT_RE)
    if pay:
        findings.append(Finding("High", "Payment/prize lure indicators", "Message contains payment, transfer, prize, or financial lure language.", 10))
        score += 10

    if re.search(r"\bdear (customer|user|account holder|sir/madam)\b", combined_lower):
        findings.append(Finding("Low", "Generic greeting", "Message uses a generic greeting instead of a personalized name.", 3))
        score += 3

    # Attachment hints in text
    attach_hits = [ext for ext in RISKY_ATTACH_HINTS if ext in combined_lower]
    # avoid duplicating explicit attachment filenames already flagged
    if attach_hits and not parsed.attachments:
        findings.append(Finding("Medium", "Risky attachment indicators", f"Message references potentially risky attachment/content types: {', '.join(sorted(set(attach_hits)))}", 7))
        score += 7

    # Combo boost
    if urls and cred:
        findings.append(Finding("Medium", "Link + credential request", "Message combines links with credential/verification requests, a common phishing pattern.", 6))
        score += 6

    # ML/statistical analysis (lightweight, explainable) - additive signal
    if enable_ml:
        try:
            ml = analyze_text_ml(combined).to_dict()
        except Exception:
            ml = {"label": "unknown", "phishing_probability": 0.0, "legitimate_probability": 0.0, "confidence": 0.0, "top_indicators": [], "model": "unavailable"}
    else:
        ml = {
            "label": "disabled",
            "phishing_probability": 0.0,
            "legitimate_probability": 0.0,
            "confidence": 0.0,
            "top_indicators": [],
            "model": "disabled by configuration",
        }

    # URL checks (hardened / evasion-resistant)
    norm_text = _normalize_obfuscated_text(combined)
    if re.search(r"\b(hxxps?|https?)\s*\[\:\]|hxxps?://|\[\.\]|\(\.\)", combined, re.IGNORECASE):
        findings.append(Finding("Medium", "Obfuscated/defanged URL indicators", "Message contains defanged or obfuscated URL patterns (e.g. hxxp, [.], [:]) often used to evade filters.", 5,
                                reasoning="Defanging can be benign in reports, but in unsolicited emails it may indicate evasion.", recommended_action="Inspect the resolved destination carefully before interacting."))
        score += 5
    for scheme in DANGEROUS_SCHEMES:
        if scheme in norm_text.lower():
            findings.append(Finding("High", "Dangerous URL scheme", f"Message contains potentially dangerous URI scheme '{scheme}'.", 12,
                                    evidence=scheme, reasoning="javascript:/data:/file: URIs can execute or embed active/misleading content.", recommended_action="Do not open or interact with such links."))
            score += 12
            break
    for u in urls:
        try:
            p = urlparse(u)
            host = (p.hostname or "").lower()
            scheme = (p.scheme or "").lower()
        except Exception:
            findings.append(Finding("Medium", "Malformed URL", f"Could not parse URL: {u}", 5))
            score += 5
            continue
        if not host:
            continue
        # IP host
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            findings.append(Finding("High", "URL uses IP address", f"Link points to raw IP host: {u}", 10))
            score += 10
        # suspicious tld
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            findings.append(Finding("Medium", "Suspicious TLD", f"Link uses higher-risk TLD '.{tld}': {u}", 6))
            score += 6
        # many subdomains / long host
        if host.count(".") >= 4 or len(host) > 40:
            findings.append(Finding("Medium", "Complex/long domain", f"Link has an unusually complex host: {host}", 5))
            score += 5
        # @ in url
        if "@" in u.split("://",1)[-1].split("/",1)[0]:
            findings.append(Finding("High", "Deceptive '@' in URL", f"URL contains '@' in authority/userinfo which can obscure the real destination: {u}", 10))
            score += 10
        # punycode / homograph hints
        if "xn--" in host:
            findings.append(Finding("High", "Punycode/IDN domain", f"Domain contains punycode (possible homograph/lookalike): {host}", 9))
            score += 9
        if _has_suspicious_unicode(host):
            findings.append(Finding("High", "Suspicious Unicode in domain", f"Domain contains non-ASCII/confusable characters: {host}", 9,
                                    reasoning="Unicode homograph characters can be used to impersonate trusted domains.", recommended_action="Manually verify the exact domain characters before trusting."))
            score += 9
        # lookalike/typosquat vs common brands
        host_skel = _confusable_skeleton(host.split(":")[0])
        for brand, legit_domains in BRAND_DOMAINS.items():
            if host_skel in legit_domains or any(host_skel.endswith("." + d) for d in legit_domains):
                continue
            # compare against brand tokens/domains
            brand_base = brand + ".com"
            dist = _levenshtein(host_skel.split(":")[0], brand_base)
            if 0 < dist <= 2 and len(host_skel) >= 6:
                findings.append(Finding("High", "Possible lookalike/typosquat domain", f"URL host '{host}' is very similar to a common brand/domain pattern '{brand_base}'.", 10,
                                        evidence=u, reasoning="Small character changes in domains are a common phishing impersonation technique.",
                                        recommended_action="Verify the domain spelling via an official bookmark or typed address."))
                score += 10
                break
        # http (not https) - stronger when credential/payment context exists
        if scheme == "http":
            pts = 4 if (cred or pay) else 3
            findings.append(Finding("Low", "Insecure HTTP link", f"Link is not using HTTPS: {u}", pts))
            score += pts
        # suspicious path/query tokens
        if re.search(r"(login|signin|verify|secure|account|update|password|wallet|invoice)", (p.path + "?" + (p.query or "")), re.IGNORECASE):
            findings.append(Finding("Medium", "Sensitive-action URL path/query", f"URL path/query contains sensitive action keywords: {u}", 4,
                                    reasoning="Legitimate services use such paths, but combined with other signals this can indicate credential harvesting.",
                                    recommended_action="Confirm the destination is the official site before entering information."))
            score += 4

    if len(urls) >= 5:
        findings.append(Finding("Medium", "Many links", f"Message contains {len(urls)} URLs, which can be a spam/phishing indicator.", 5))
        score += 5

    # Cap and verdict
    score = max(0, min(100, int(score)))
    verdict = _score_to_verdict(score)

    # Deduplicate similar finding titles+details lightly
    uniq = []
    seen = set()
    for f in findings:
        key = (f.title, f.detail)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    findings = sorted(uniq, key=lambda x: (-x.score, x.severity, x.title))

    # Category score breakdown (approximate, for reporting)
    cat = {"header_identity": 0, "authentication": 0, "url": 0, "content": 0, "attachment": 0, "other": 0}
    for f in findings:
        cat[_finding_category(f)] += int(getattr(f, "score", 0) or 0)

    if not findings:
        summary = "No strong phishing indicators detected by heuristic checks."
    else:
        top = "; ".join(f.title for f in findings[:3])
        summary = f"Detected {len(findings)} indicator(s). Top signals: {top}."
    if ml.get("label") in ("phishing", "legitimate"):
        summary += f" ML: {ml.get('label')} ({int(round(float(ml.get('phishing_probability', 0))*100))}% phishing likelihood)."

    if whitelist:
        wl_counts = {k: len(v) for k, v in observables.get("whitelisted", {}).items()}
        if sum(wl_counts.values()) > 0:
            findings.append(Finding("Low", "Whitelist applied", f"Some extracted observables were whitelisted and excluded from risky URL scoring: {wl_counts}", 0))

    resolved_auth = auth_details if 'auth_details' in locals() else {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "sources": parsed.auth_results}
    recommendations = build_recommendations(verdict, findings, resolved_auth)
    security_assessment = build_security_assessment(
        verdict=verdict,
        score=score,
        findings=findings,
        auth=resolved_auth,
        category_scores=cat,
    )

    metadata = {
        "subject": parsed.subject,
        "from": parsed.sender,
        "reply_to": parsed.reply_to,
        "to": parsed.to,
        "date": parsed.date,
        "message_id": parsed.message_id,
        "return_path": parsed.return_path,
        "received_count": len(parsed.received),
        "attachment_count": len(parsed.attachments),
        "attachments": parsed.attachments,
        "url_count": len(urls),
        "all_url_count": len(all_urls),
        "ml_enabled": bool(enable_ml),
        "whitelist_path": whitelist_path or "",
        "whitelist_applied": bool(whitelist),
    }

    return ScanResult(
        verdict=verdict,
        score=score,
        findings=findings,
        urls=urls,
        summary=summary,
        metadata=metadata,
        auth_analysis=resolved_auth,
        observables=observables,
        whitelist_applied=bool(whitelist),
        ml_analysis=ml,
        category_scores=cat,
        recommendations=recommendations,
        security_assessment=security_assessment,
    )


def scan_email(
    text: str,
    whitelist_path: Optional[str] = None,
    use_default_whitelist: bool = False,
    enable_ml: bool = True,
) -> ScanResult:
    parsed = parse_email_text(text)
    wl_path = whitelist_path or (_default_whitelist_path() if use_default_whitelist else None)
    wl = load_whitelist(wl_path)
    result = analyze_parsed(parsed, whitelist=wl, enable_ml=enable_ml, whitelist_path=wl_path)
    result.source = "text"
    return result


def scan_email_file(
    path: str,
    whitelist_path: Optional[str] = None,
    use_default_whitelist: bool = False,
    enable_ml: bool = True,
) -> ScanResult:
    parsed = parse_email_file(path)
    wl_path = whitelist_path or (_default_whitelist_path() if use_default_whitelist else None)
    wl = load_whitelist(wl_path)
    result = analyze_parsed(parsed, whitelist=wl, enable_ml=enable_ml, whitelist_path=wl_path)
    result.source = str(path)
    return result
