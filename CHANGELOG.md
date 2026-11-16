# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where practical.

## [Unreleased]

### Added
- **Security framework module** (`phishguard/threat_framework.py`): offline **CVSS v3.1 base-score calculator** (`--cvss-vector`), evidence-linked **MITRE ATT&CK** technique mappings, relevant **CWE** references, and a clearly labeled triage CVSS estimate in every scan. CVE references are not auto-attributed from email content (product/version-specific).
- `ScanResult.security_assessment` and report/CLI/GUI/case metadata integration for MITRE/CWE/CVSS context.
- Input hardening: raw text character limit in `parse_email_text` and file size limit enforcement for safer parsing; CLI single-scan errors handled cleanly.
- Security tests (`tests/test_security.py`) covering CVSS calculation, mappings, assessment shape, and size-limit protections.
- MIT `LICENSE`, `.gitignore`, and GitHub/community documentation (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, issue/PR templates).
- ThePhish reverse-engineering and PhishGuard planning artifacts in `analysis/` (architecture/execution/data/integration maps, feature registry, security audit, gap analysis, implementation roadmap, licensing/attribution).
- Design and operational docs in `docs/` (`ARCHITECTURE.md`, `ORCHESTRATION.md`, `DETECTION_METHODOLOGY.md`, `INTEGRATIONS.md`, `CONFIGURATION.md`, `TESTING.md`) and generated example outputs in `docs/examples/`.
- Additive investigation and integration foundations: `phishguard/investigation.py` (evidence hashing/provenance, observable normalization/dedup, analyzer result normalization, investigation case/timeline models, `scan_result_to_investigation`) and `phishguard/integrations/` (provider contracts and safe null provider).
- **Every scan now creates an investigation case** (evidence hash, normalized analyzer result, timeline) with analyst verdict/note actions and local case JSON export.
- **Functional provider registry** (`phishguard.integrations.registry`): `LocalCaseExportProvider` writes case JSON locally; `NullExportProvider` remains the safe fallback; no external/network provider is enabled.
- `ScanResult.recommendations` with `build_recommendations()` in `scanner.py`; recommendations are included in JSON, HTML, CLI, GUI, and case metadata.
- Whitelist editing/validation helpers (`validate_whitelist`, `whitelist_summary`, `add_exact_rule`) that preserve PhishGuard and ThePhish-compatible schemas and write atomically.
- GUI wiring for the whole workflow: case panel/timeline/analyst actions, observable copy/add-to-whitelist/rescan, whitelist reload/clear/validation, findings copy actions, session-history reload/delete/clear, activity copy/clear, risk gauge, ML toggle, and one-click Paste & Scan.
- Background GUI batch scanning with progress, cancellation, double-click result loading, batch JSON/HTML export, and one-case-per-file export.
- CLI additions: `--case`, `--case-dir`, `--no-ml`, `--version`, batch HTML export, and whitelist validation before scanning.
- Automated tests for recommendations, category-score totals, ML toggle, whitelist editing/validation, local case provider/registry, case analyst actions, single/batch HTML, CLI case/ML/whitelist flows, security assessment/CVSS/MITRE/CWE mappings, and input size limits. Test suite: 45 tests passing.

### Changed
- GUI restyled to a soft navy/blue dashboard theme (pale blue canvas, white cards, deep navy sidebar/header, navy accent buttons, pill/segment styling, and a circular risk gauge). The Report tab is scrollable so content is reachable at smaller window sizes.
- HTML single and batch reports use the same navy/blue dashboard styling (rounded cards, soft shadows, pill badges) while remaining fully self-contained and dependency-free.
- GUI remains an email-client-style inbox: mailbox sidebar, scanned-message list, and a reading pane with From/To/Date/Auth header, verdict stamp, warning banner, and parsed message body. Raw input lives in a dedicated Source tab; scan details split into Report/Details tabs.
- Batch scans now run off the UI thread; while running, single scans are blocked with a clear message and the Cancel button is enabled.
- Reports now use stored recommendations when present; batch HTML includes a summary badge row, scan index, per-file findings, and recommended actions.
- Documentation updated for case/integration/whitelist/batch/ML behavior.
- Removed stale root-level `example_report.html`/`example_report.json`; canonical examples live in `docs/examples/`.

### Fixed
- Category risk points now sum exactly to finding score totals (deterministic category mapping).
- Whitelist filename rules are honored for attachment metadata checks.
- ML can be disabled cleanly without breaking report fields (`label: disabled`).
- HTML report generation no longer emits Python 3.12+ `datetime.utcnow()` deprecation warnings.

## [0.3.0] - 2026-04-11

### Added
- One-click **Paste & Scan** workflow for Gmail “Show original” raw source in the GUI.
- Lightweight embedded ML/statistical analysis (`phishguard/ml_model.py`, Multinomial Naive Bayes) with phishing likelihood, confidence, and top indicators.
- Full report enhancements: recommended actions, ML analysis, and category risk breakdown in CLI/GUI/JSON/HTML outputs.
- Parallel/multi-core batch scanning in CLI via `--jobs` (`ProcessPoolExecutor`).
- Hardened detection checks: defanged/obfuscated URL normalization, dangerous URI schemes, IDN/punycode and Unicode/confusable/zero-width indicators, lookalike/typosquat hints, advanced header/identity forensics (e.g. Message-ID domain mismatch, freemail-role impersonation, empty-subject/hidden-HTML signals), and expanded URL/content heuristics.
- Realistic Gmail “Show original” LinkedIn job-alert sample fixture and corresponding tests.

### Changed
- Precompiled detection patterns and improved scanning/reporting performance and clarity.
- GUI/CLI/report UX to better present verdict, score, auth (unverified header claims), ML, observables, and findings.
- README expanded with detailed features, workflow, usage, limitations, and safety notes.

### Fixed
- Reduced false positives (e.g. credential-pattern matches in URL tokens like `otpToken`) and improved handling of related envelope domains (e.g. `bounce.linkedin.com` vs `linkedin.com`).

## [0.2.0]

### Added
- Enhanced GUI (tabbed workflow), batch scanning/reporting, observables extraction, whitelist support, HTML/JSON exports, and analysis logging.
- Authentication header parsing (SPF/DKIM/DMARC/Received-SPF as header claims), additional header/URL/content/attachment heuristics.

## [0.1.0]

### Added
- Initial PhishGuard Mail Scanner with heuristic phishing analysis, CLI/GUI basics, sample emails, and core parsing/scoring/reporting.
