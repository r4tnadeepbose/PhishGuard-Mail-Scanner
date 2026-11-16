# Implementation Roadmap (PhishGuard Ultimate)

**Date:** 2026-11-17  
**Principle:** Incremental evolution, backward compatibility for existing CLI/GUI behavior, security-first defaults, no fabricated capabilities.

## Phase 0 — Reconnaissance & Baseline (Completed in this pass)
**Goals**
- Inspect repository architecture, modules, samples, docs, and runtime behavior.
- Execute existing CLI flows and establish baseline outcomes.
- Identify defects/risks and perform targeted reliability fixes.
- Produce research/competitor analysis and feature registry.

**Delivered**
- Baseline inspection and execution: single scan, JSON/HTML export, batch scan, CLI regression checks; GUI compile-checked (interactive visual validation limited by environment).
- Fixes: calibrated 0–100 scoring/verdicts, explicit unverified auth-header caveat, improved display-name heuristic/noise reduction, parser file-size limit (5 MB), enriched finding fields, CLI exit alignment.
- Tests: `tests/test_scanner.py`, `tests/test_cli.py`, `tests/test_investigation.py`, `tests/test_whitelist.py`, `tests/test_report.py` (**39 tests passing** via unittest).
- Docs: `docs/RESEARCH_AND_COMPETITOR_ANALYSIS.md`, `docs/FEATURE_REGISTRY.md`, this roadmap; README updated for limitations/calibrated model; example reports generated.

## Phase 0.5 — Connected Workflow & Investigation Foundations (Completed in this pass)
**Delivered**
- Every scan creates an `InvestigationCase` (SHA-256 evidence, normalized analyzer result, timeline) with analyst verdict/notes and local case JSON export.
- Functional provider registry (`DEFAULT_REGISTRY`) with `LocalCaseExportProvider`; external adapters remain disabled.
- Context-aware recommendations generated in the scanner and reused in JSON/HTML/CLI/GUI/case metadata.
- Whitelist validation/summary/exact-rule editing that preserves PhishGuard and ThePhish-compatible schemas.
- CLI `--case`, `--case-dir`, `--no-ml`, `--version`, batch HTML; GUI case panel, background batch with progress/cancel, history reload/delete, observable copy/add-to-whitelist/rescan.
- GUI restyled to a navy/blue dashboard theme (pale blue canvas, white cards, deep navy sidebar/header, navy accent) with a circular risk gauge and scrollable Report tab.
- Test suite expanded to **39 tests**; local GUI smoke test covers scan → case → analyst actions → history → batch → exports.

**Known limitations carried forward**
- No independent SPF/DKIM/DMARC/ARC verification (header claims only).
- No live threat-intel/reputation, redirect chasing, sandboxing, or attachment detonation.
- Heuristic detection only (false positives/negatives possible).

## Phase 1 — Core Reliability & Trust Boundaries (P0/P1, next)
**Scope**
- Harden parser: stricter MIME/encoding/attachment-metadata handling, part/recursion/count guards, oversized/malformed corpus tests.
- Normalize IOC extraction/defanging and improve URL/domain/email parsing consistency.
- Strengthen auth context: clearer provenance labeling (claimed vs unavailable), header conflict/duplication surfacing.
- Modularize detection into a lightweight rule/finding pipeline (safe isolation per rule/analyzer).
- Expand automated tests and regression fixtures (no real data exfiltration).

**Acceptance**
- Existing commands and report generation remain functional.
- New tests cover added edge cases; no crash on malformed inputs in supported limits.

## Phase 2 — Detection Expansion (P1/P2)
**Scope**
- Enhanced phishing/content indicators (obfuscation, hidden HTML cues, link-text vs href mismatches where safely parsable).
- Attachment static metadata improvements (hashes, magic/MIME mismatch checks) with strict size/resource controls.
- Optional local-only analyzers (e.g. configurable pattern/YARA hooks) behind feature flags.
- Improved forensic reporting sections and schema versioning.

**Acceptance**
- All new analyzers optional/configurable and independently testable.
- No attachment execution; no network calls by default.

## Phase 3 — Threat Intelligence & Enrichment (P2/P3, opt-in)
**Scope**
- Provider adapter interface with: explicit user consent, API key management, caching, rate limiting, timeouts, retries, failure isolation, provenance.
- Safe enrichment targets (hash/URL/domain lookups) without uploading full sensitive email content by default.
- Local feed/cache support where licensing permits.

**Acceptance**
- Disabled by default; clear privacy warnings; audited logging of outbound requests (when enabled).
- **Blocked/Deferred if keys/infra/consent unavailable** — adapters and docs provided instead of fake integrations.

## Phase 4 — SOC Workbench, Cases & Forensics (P2/P3)
**Scope**
- Evidence provenance records (hash/timestamps/source), investigation timeline data model.
- Optional local persistence (SQLite, repository abstraction) for scan/case metadata (minimized sensitive storage).
- Incremental GUI/API improvements for investigation workflows and visualizations driven by real data.

**Already delivered (Phase 0.5):** evidence SHA-256/provenance, case/timeline model, analyst verdict/notes, local case JSON export, GUI case panel, and batch per-file cases.

**Remaining:** database-backed persistence and repository abstraction beyond exported JSON.

**Acceptance**
- Original evidence never modified; retention/config controls documented.
- Backward-compatible CLI/standalone scanning preserved.

## Phase 5 — AI & ML (P3/P4, optional, gated)
**Scope**
- AI assistant **only** as evidence-grounded summarization/explanation with prompt-injection isolation and no auto-actions (no browsing/execution).
- ML pipeline only with reproducible datasets/licensing, evaluation metrics, and no unverified accuracy claims.

**Acceptance**
- Fully optional; rule-based engine remains authoritative fallback.
- **Deferred** until safety, provenance, and benchmark requirements are met.

## Phase 6 — Enterprise Readiness & Release (P2/P3)
**Scope**
- Optional localhost-first REST API with validation/auth/rate limits/OpenAPI docs.
- Hardening (threat model, SSRF/path/archive/input controls), lint/type/security checks (ruff/mypy/bandit/pip-audit) as compatible.
- Packaging, CI, SBOM/license inventory, and release documentation.

**Acceptance**
- Secure defaults, reproducible builds where practical, no secret leakage.

## Cross-cutting requirements (all phases)
- Preserve existing CLI invocations and GUI usability; add compatibility layers for new command structures.
- Every significant change: tests + regression check + docs + feature registry update.
- Mark unavailable integrations/capabilities as **Deferred/Blocked** with reasons; never fabricate results or verification.
- Prioritize detection accuracy, transparency, security, and reliability over feature count.
