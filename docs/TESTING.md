# Testing

## 1. Test philosophy

PhishGuard tests should validate correctness, safety, and explainability of local email analysis without relying on real external services or live malicious infrastructure.

- **Deterministic and local:** use fixtures/sanitized samples and mocks.
- **Safe:** never execute attachments, never browse suspicious URLs, never send data to third parties.
- **Regression-focused:** preserve existing behavior unless an intentional, documented improvement is made.
- **Evidence-based:** tests must reflect actual implemented behavior (no fabricated results).

## 2. Current automated tests

Located in `tests/`:
- `tests/test_scanner.py` — scanner/parser/heuristic behavior, observables/whitelisting, detection regressions (including Gmail “Show original” legitimate sample handling), recommendations, category totals, ML toggle, whitelist metadata, security assessment presence.
- `tests/test_cli.py` — CLI scan/batch/report/output behavior, case export, batch case directory, `--no-ml`, whitelist validation, batch HTML.
- `tests/test_investigation.py` — evidence hashing, observable dedup, case/timeline, analyst actions, null/local export providers, registry.
- `tests/test_whitelist.py` — validation, summary, exact-rule editing, schema preservation, bad input.
- `tests/test_report.py` — single/batch HTML rendering, stored recommendations, error rows.
- `tests/test_security.py` — CVSS v3.1 calculator, triage estimate, MITRE ATT&CK/CWE mappings, security assessment shape, input/file size limits.

Current suite: **45 tests passing** via `python -m unittest discover -s tests -p "test_*.py"`.

Sample fixtures: `samples/` (e.g. phishing/legitimate/raw and `.eml` cases, including `linkedin_job_alert_show_original.eml`).

## 3. Running tests

From the project root (`C:\Users\boser\Downloads\PhishGuard-Mail-Scanner`):

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Run specific modules during development:

```bash
python -m unittest tests.test_scanner
python -m unittest tests.test_cli
```

## 4. Recommended test coverage (by area)

### Parsing and ingestion
- Raw RFC822 and simple header/body inputs
- MIME multipart/nested structures, encodings/charsets, malformed boundaries
- HTML/text extraction, attachment metadata, received/auth header capture
- Size-limit enforcement (`MAX_PARSE_BYTES`) and safe failure on oversized/malformed input

### Observables and whitelisting
- URL/domain/IP/email extraction, normalization/defang, deduplication
- IDN/punycode/confusable/zero-width and lookalike indicators
- Whitelist schema compatibility (PhishGuard and ThePhish-compatible), exact/regex/domain-scoped matches
- Whitelist bypass attempts and over-broad rule behavior (documented)

### Detection and verdicting
- Benign, suspicious, phishing, and edge-case fixtures with expected verdict/score bands
- Header identity/auth-claim findings (labeled as unverified claims)
- URL/content/attachment/HTML-evasion indicators
- Embedded ML output presence/stability (label/likelihood/confidence/indicators) where deterministic
- Correlation/normalization cases: conflicting signals, missing/unknown/error inputs must not produce “safe” by default

### Orchestration and jobs (target/additive)
- Analyzer registry resolution and applicability
- Bounded concurrency, timeouts, cancellation, retries (safe/idempotent only)
- Result collection, deduplication, provenance, and partial-failure isolation
- Progress events reflect real backend state

### Investigation/case/reporting
- Evidence hashing/provenance, timeline ordering, automated vs analyst-confirmed verdict separation — covered by `tests/test_investigation.py`.
- JSON/HTML report schema/content, redaction behavior, export correctness — covered by `tests/test_report.py` and `tests/test_cli.py`.
- Case serialization and local export through `DEFAULT_REGISTRY` — covered by `tests/test_investigation.py`.

### Integrations (target/additive, optional)
- Adapter config validation (disabled-by-default, TLS/secret handling)
- Mocked IMAP/TheHive/Cortex/MISP/notification flows (success, timeout, auth failure, malformed response)
- No core dependency: local scans succeed with integrations absent or failing

### CLI/GUI
- CLI argument parsing, stdin/file/batch modes, `--jobs`, JSON/HTML output, exit behavior
- GUI logic/state helpers where testable (non-interactive); manual smoke checks for rendering/workflows

## 5. Fixtures and mocking guidelines

- Store fixtures under `samples/` or `tests/fixtures/` with sanitized/redacted content only.
- Prefer small, focused `.eml`/text cases per behavior; include provenance comments in test names/docstrings.
- Mock network/process boundaries (`imaplib`, HTTP clients, provider SDKs, mailers, clocks/timeouts) using standard unittest mocks.
- Do not depend on system-specific mail clients, local mailboxes, or internet access.

## 6. Manual validation checklist

- `python main.py` launches GUI and can scan pasted “Show original” samples.
- `python cli.py <sample.eml> --json` produces valid, explainable output.
- Batch scan with `--jobs` matches single-scan results for the same inputs.
- Reports/exports contain no secrets and clearly label auth data as header claims.
- Optional integrations (if configured) are explicit, auditable, and safely degradable.

## 7. CI/release expectations

- All unit/integration tests pass on supported Python versions/platform targets.
- New detection/orchestration behavior includes tests and documentation updates.
- Known limitations and intentional verdict changes are recorded in `CHANGELOG.md` and relevant docs. 
