# PhishGuard Implementation Roadmap (ThePhish-Inspired, Independent)

## 1. Goals and constraints

- **Goal:** evolve PhishGuard into a more capable local email security investigation platform inspired by ThePhish’s orchestration/investigation concepts (IOC extraction/whitelisting, analyzer coordination, normalization, case/evidence workflows, optional SOC integrations) while preserving current strengths.
- **Constraints:** local/offline-first by default; no attachment execution; no auto-browsing suspicious URLs; no default third-party uploads; preserve existing CLI/GUI/API behavior where practical; keep external integrations optional; do not copy ThePhish AGPL code into MIT codebase; do not fabricate features/tests.

## 2. Current baseline (to preserve)

- Entry points: `main.py`, `gui.py`, `cli.py`, package API (`scan_email`, `scan_email_file`).
- Core modules: `phishguard/parser.py`, `phishguard/scanner.py`, `phishguard/ml_model.py`, `phishguard/whitelist.py`, `phishguard/report.py`.
- Existing capabilities: raw/EML parsing, heuristic + embedded ML analysis, observables, whitelist support (incl. ThePhish-compatible schema), JSON/HTML reports, batch/history/export, parallel CLI jobs.
- Validation baseline: `python -m unittest discover -s tests -p "test_*.py"` (14 tests passing at last recorded run).

> **Current-status note (2026-11-17):** baseline has advanced. Cases/evidence/timeline, analyst actions, local case export through a provider registry, recommendations, whitelist validation/editing, and background batch scanning are implemented; the suite is now **39 tests passing**. See `docs/FEATURE_REGISTRY.md`, `docs/ORCHESTRATION.md`, and `docs/IMPLEMENTATION_ROADMAP.md`.

## 3. Roadmap phases

### Phase A — Foundation and data contracts (highest priority)
**Deliverables**
- Internal models for `Evidence`, `Observable`, `AnalyzerResult`, `NormalizedFinding`, `Verdict`, `InvestigationCase`, `TimelineEvent` (additive; can live under `phishguard/core/` or `phishguard/models.py`).
- Evidence integrity utilities: original-input hash (raw/EML), attachment/observable hashes, timestamps, source/provenance fields.
- Observable extraction/normalization/dedup module (URL/domain/IP/email/hash/filename) with defang + Unicode handling and whitelist decision records.
- Typed config loading/validation for scan/orchestration/integration settings (safe defaults).

**Acceptance criteria**
- Existing scan API and report fields remain backward-compatible.
- New models serializable to JSON and usable by CLI/GUI/reporting.
- Unit tests for normalization, hashing/provenance, and config validation.

### Phase B — Local analyzer registry and orchestration
**Deliverables**
- Analyzer interface/registry: id, name, version, supported observable types, requirements, timeout, enabled flag, output schema.
- Dispatcher/job manager/result collector: bounded local concurrency, per-analyzer timeout/error isolation, cancellation hooks, deterministic result ordering.
- Wrap current engines as analyzers/adapters: `heuristic_headers_auth`, `url_content`, `attachment`, `embedded_ml`, etc., producing structured results.
- Progress/event model for UI/CLI (real backend events, not simulated).

**Acceptance criteria**
- Default local scan path uses orchestration internally but returns equivalent/compatible results.
- Analyzer failure produces `error/unknown` result (never treated as safe) with preserved diagnostics.
- Tests for dispatcher behavior, timeouts, duplicates, and partial failures.

### Phase C — Severity normalization, correlation, and verdict engine
**Deliverables**
- Severity normalizer mapping raw/local/provider levels to `informational/safe/suspicious/malicious/unknown/error` while preserving original outputs.
- Correlation/scoring layer combining authentication, header anomalies, observables, content, attachments, ML, and optional provider intelligence.
- Explainable verdict object: final verdict, confidence/risk rationale, contributing/contradicting evidence, unknowns/gaps.
- Policy: missing critical evidence or analyzer errors cannot auto-force “safe”.

**Acceptance criteria**
- Verdict explanations traceable to evidence/findings.
- Regression tests ensure no false-safe downgrade on missing/error states and maintain existing sample expectations.

### Phase D — Investigation workflow, case/evidence, and reporting
**Deliverables**
- Investigation lifecycle support: ingest/validate → preserve evidence → parse → extract/whitelist → analyze → correlate → verdict → case/timeline → export.
- Case manager storing automated verdict separate from analyst-confirmed verdict, notes, status, IOC inventory, and timeline events.
- Enhanced JSON/HTML reports including evidence hashes, provenance, analyzer results, normalization, and timeline summary.
- Example investigation + example JSON/HTML report fixtures (sanitized).

**Acceptance criteria**
- Reports remain readable in CLI/GUI and machine-consumable in JSON.
- Evidence/provenance included without leaking secrets/unsafe auto-actions.
- Tests for case serialization, timeline ordering, and report schema stability.

### Phase E — Optional integration adapters (provider-agnostic)
**Deliverables**
- Interfaces/adapters (disabled by default): `imap_ingestion`, `thehive_case`, `cortex_analyzer`, `misp_export`, `notification`.
- ThePhish-compatible mapping layer where useful (config/whitelist/observable export semantics) implemented independently.
- Mocked adapters and contract tests; no real external services required.
- Secure credential/config handling (env/secret references, redaction, TLS validation options).

**Acceptance criteria**
- `python main.py` and `python cli.py` work with no integrations configured.
- Integration failures isolated and reported; core verdict/report still produced when possible.
- No AGPL code copied; attribution/licensing notes updated.

### Phase F — UI/CLI and quality hardening
**Deliverables**
- CLI: investigation/case commands or flags, structured progress, optional adapter toggles, stable JSON output.
- GUI: investigation queue/history view, analyzer/progress status, evidence/verdict explanation panels (real state only).
- Documentation: `docs/ARCHITECTURE.md`, `docs/ORCHESTRATION.md`, `docs/DETECTION_METHODOLOGY.md`, `docs/INTEGRATIONS.md`, `docs/CONFIGURATION.md`, `docs/TESTING.md`.
- Test expansion: parser/MIME edge cases, observables/whitelist bypass attempts, dispatcher timeouts/failures/conflicts, adapter mocks, report/case generation.

**Acceptance criteria**
- All existing and new automated tests pass.
- Documentation reflects actual implemented behavior and optional/non-optional components.

## 4. Incremental implementation order (recommended)

1. Add models + evidence hashing/provenance utilities (no behavior change).
2. Introduce local analyzer interfaces and wrap existing scanner/ML logic.
3. Add normalizer/correlator and integrate into `scan_email*` with compatibility layer.
4. Add investigation/case/timeline + enriched reports/fixtures.
5. Add optional adapter interfaces and mocks.
6. Update CLI/GUI/docs/tests; run full validation after each step.

## 5. Testing and validation plan

- **Automated:** `python -m unittest discover -s tests -p "test_*.py"` plus new module tests under `tests/`.
- **Fixtures:** sanitized `.eml`/raw samples for benign, phishing, malformed MIME, nested attachments, obfuscated/IDN URLs, whitelist edge cases.
- **Mocking:** external HTTP/APIs/mailbox/providers fully mocked; no real accounts or production SOC systems.
- **Non-regression:** preserve current verdicts/findings for existing samples unless an intentional, documented improvement is made.

## 6. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| AGPL contamination from ThePhish | Licensing/compliance issues | Independent implementation, trace ideas not code, maintain `LICENSING_AND_ATTRIBUTION.md` |
| Regression in local scan behavior | User trust/broken workflows | Compatibility layer, snapshot/fixture tests, incremental rollout |
| Complexity/performance overhead | Slower scans/UI lag | Lazy adapter loading, bounded concurrency, profiling, keep stdlib-first core |
| Unsafe integration defaults | Data leakage/network actions | Opt-in integrations, secure config validation, redaction, explicit user actions |
| False-safe on missing evidence | Missed threats | Unknown/error states, confidence-aware verdict policy, analyst review cues |

## 7. Definition of done (for this program increment)

- Required `analysis/*.md` and `docs/*.md` artifacts created and evidence-based.
- PhishGuard gains modular orchestration/normalization/investigation foundations and optional adapter interfaces without breaking core local usage.
- New/updated tests cover added behavior and pass alongside existing tests.
- Licensing/attribution clearly documents ThePhish AGPL study vs original PhishGuard implementation. 
