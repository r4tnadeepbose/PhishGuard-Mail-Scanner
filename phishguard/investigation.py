"""Independent, additive investigation/orchestration models inspired by common SOC workflows.

This module does not copy ThePhish (AGPL-3.0) code. It provides local data models and
helpers for evidence provenance, normalized findings, and investigation timelines that can
wrap existing PhishGuard scan results.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

try:
    from .scanner import ScanResult  # type: ignore
except Exception:  # pragma: no cover
    ScanResult = Any  # fallback for isolated imports


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).digest().hex()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data or b"").digest().hex()


def make_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


SEVERITY_ORDER = {
    "error": 5,
    "malicious": 4,
    "suspicious": 3,
    "unknown": 2,
    "informational": 1,
    "safe": 0,
}

LOCAL_SEVERITY_MAP = {
    "high": "malicious",
    "medium": "suspicious",
    "low": "informational",
    "critical": "malicious",
    "info": "informational",
}


def normalize_severity(value: Optional[str]) -> str:
    v = (value or "").strip().lower()
    if not v:
        return "unknown"
    if v in SEVERITY_ORDER:
        return v
    return LOCAL_SEVERITY_MAP.get(v, "unknown")


@dataclass
class EvidenceItem:
    evidence_id: str
    kind: str  # raw_email, eml_file, attachment, report, etc.
    name: str
    sha256: str
    size: Optional[int] = None
    source: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Observable:
    obs_type: str  # url, domain, ip, email, hash, file, message_id, etc.
    value: str
    normalized: str = ""
    source: str = ""
    tags: List[str] = field(default_factory=list)
    whitelisted: bool = False
    provenance: Dict[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        return f"{self.obs_type}:{(self.normalized or self.value).lower()}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def normalize_observable_value(obs_type: str, value: str) -> str:
    v = (value or "").strip()
    t = (obs_type or "").lower()
    if t in {"domain", "email", "url", "message_id"}:
        v = v.lower()
    if t == "domain":
        v = v.strip(".")
    if t == "url":
        v = v.rstrip(".,;)")
    return v


def dedupe_observables(observables: Iterable[Observable]) -> List[Observable]:
    seen: Dict[str, Observable] = {}
    for obs in observables:
        if not obs.normalized:
            obs.normalized = normalize_observable_value(obs.obs_type, obs.value)
        k = obs.key()
        if not k or k.endswith(":"):
            continue
        if k not in seen:
            seen[k] = obs
        else:
            # merge tags/provenance conservatively
            existing = seen[k]
            for tag in obs.tags:
                if tag not in existing.tags:
                    existing.tags.append(tag)
            existing.whitelisted = existing.whitelisted or obs.whitelisted
            if obs.source and not existing.source:
                existing.source = obs.source
    return list(seen.values())


@dataclass
class AnalyzerResult:
    analyzer_id: str
    name: str
    status: str  # succeeded, failed, timed_out, skipped
    severity: str = "unknown"
    confidence: float = 0.0
    summary: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    observables: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = normalize_severity(self.severity)
        return d


@dataclass
class TimelineEvent:
    event_id: str
    timestamp: str
    event_type: str
    message: str
    actor: str = "system"
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationCase:
    case_id: str
    title: str
    status: str = "open"  # open, in_progress, closed
    automated_verdict: str = "Unknown"
    analyst_verdict: Optional[str] = None
    risk_score: int = 0
    evidence: List[EvidenceItem] = field(default_factory=list)
    observables: List[Observable] = field(default_factory=list)
    analyzer_results: List[AnalyzerResult] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    notes: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_event(self, event_type: str, message: str, actor: str = "system", data: Optional[Dict[str, Any]] = None) -> TimelineEvent:
        ev = TimelineEvent(
            event_id=make_id("evt"),
            timestamp=utc_now_iso(),
            event_type=event_type,
            message=message,
            actor=actor,
            data=data or {},
        )
        self.timeline.append(ev)
        self.updated_at = utc_now_iso()
        return ev

    def set_analyst_verdict(self, verdict: Optional[str], actor: str = "analyst", note: str = "") -> TimelineEvent:
        """Record an analyst decision without overwriting the automated verdict."""
        self.analyst_verdict = verdict or None
        self.status = "closed" if verdict else "in_progress"
        message = f"Analyst verdict set to {verdict}" if verdict else "Analyst verdict cleared"
        if note:
            message += f": {note}"
        return self.add_event("analyst_verdict", message, actor=actor, data={"analyst_verdict": self.analyst_verdict})

    def add_note(self, text: str, actor: str = "analyst") -> TimelineEvent:
        text = (text or "").strip()
        if not text:
            raise ValueError("Note text is empty.")
        note = {"note_id": make_id("note"), "text": text, "actor": actor, "created_at": utc_now_iso()}
        self.notes.append(note)
        return self.add_event("note_added", text, actor=actor, data={"note_id": note["note_id"]})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "status": self.status,
            "automated_verdict": self.automated_verdict,
            "analyst_verdict": self.analyst_verdict,
            "risk_score": self.risk_score,
            "evidence": [e.to_dict() for e in self.evidence],
            "observables": [o.to_dict() for o in self.observables],
            "analyzer_results": [a.to_dict() for a in self.analyzer_results],
            "timeline": [t.to_dict() for t in self.timeline],
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }


def scan_result_to_investigation(result: ScanResult, raw_email_text: str = "", source: str = "", title: Optional[str] = None) -> InvestigationCase:
    """Create an investigation case from an existing PhishGuard ScanResult (additive helper)."""
    src = source or getattr(result, "source", "") or "input"
    meta = getattr(result, "metadata", {}) or {}
    case_title = title or meta.get("subject") or f"Email investigation: {src}"
    case = InvestigationCase(case_id=make_id("case"), title=str(case_title), automated_verdict=getattr(result, "verdict", "Unknown"), risk_score=int(getattr(result, "score", 0) or 0))
    if raw_email_text:
        case.evidence.append(EvidenceItem(
            evidence_id=make_id("ev"),
            kind="raw_email",
            name=src,
            sha256=sha256_text(raw_email_text),
            size=len(raw_email_text.encode("utf-8", errors="replace")),
            source=src,
            metadata={"parser_source": src},
        ))
    case.add_event("scan_imported", "Imported existing PhishGuard scan result", data={"source": src, "verdict": case.automated_verdict, "score": case.risk_score})

    obs_dict = getattr(result, "observables", {}) or {}
    collected: List[Observable] = []
    for otype in ("urls", "domains", "ips", "emails"):
        for val in (obs_dict.get(otype) or []):
            collected.append(Observable(obs_type=otype[:-1] if otype.endswith('s') else otype, value=str(val), normalized=normalize_observable_value(otype[:-1] if otype.endswith('s') else otype, str(val)), source="scan_result"))
    wl = obs_dict.get("whitelisted") or {}
    for otype in ("urls", "domains", "ips", "emails"):
        for val in (wl.get(otype) or []):
            collected.append(Observable(obs_type=otype[:-1] if otype.endswith('s') else otype, value=str(val), normalized=normalize_observable_value(otype[:-1] if otype.endswith('s') else otype, str(val)), source="scan_result", whitelisted=True, tags=["whitelisted"]))
    case.observables = dedupe_observables(collected)

    findings = []
    for f in (getattr(result, "findings", []) or []):
        if hasattr(f, "__dict__"):
            findings.append({k: v for k, v in f.__dict__.items()})
        elif isinstance(f, dict):
            findings.append(f)
    analyzer = AnalyzerResult(
        analyzer_id="phishguard.local_heuristic_ml",
        name="PhishGuard Local Heuristic+ML",
        status="succeeded",
        severity="malicious" if case.risk_score >= 70 else "suspicious" if case.risk_score >= 20 else "informational",
        confidence=float((getattr(result, "ml_analysis", {}) or {}).get("confidence", 0.0) or 0.0),
        summary=getattr(result, "summary", ""),
        findings=findings,
        raw=result.to_dict() if hasattr(result, "to_dict") else {"verdict": case.automated_verdict, "score": case.risk_score},
        started_at=case.created_at,
        finished_at=case.created_at,
    )
    case.analyzer_results.append(analyzer)
    case.metadata.update({
        "source": src,
        "auth_analysis": getattr(result, "auth_analysis", {}) or {},
        "ml_analysis": getattr(result, "ml_analysis", {}) or {},
        "category_scores": getattr(result, "category_scores", {}) or {},
        "recommendations": list(getattr(result, "recommendations", []) or []),
        "security_assessment": getattr(result, "security_assessment", {}) or {},
    })
    return case


def case_to_json(case: InvestigationCase) -> str:
    return json.dumps(case.to_dict(), indent=2, ensure_ascii=False)
