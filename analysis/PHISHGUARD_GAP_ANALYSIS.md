# PhishGuard Gap Analysis (vs ThePhish)

**PhishGuard inspected:** `C:\Users\boser\Downloads\PhishGuard-Mail-Scanner` — `main.py`, `gui.py`, `cli.py`, `phishguard/{__init__,parser,scanner,ml_model,whitelist,report}.py`, `tests/{test_scanner.py,test_cli.py}`, `README.md`, `samples/*`, `requirements.txt`, `whitelist.json`, GitHub/docs artifacts. **Tests observed:** 14/14 passing previously (`python -m unittest discover -s tests -p "test_*.py"`).

> **Current-status note (2026-11-17):** this document is the original point-in-time gap analysis. Several gaps have since been closed in-repo: investigation case/timeline + analyst workflow (`phishguard/investigation.py`), local case export provider registry (`phishguard/integrations/`), context-aware recommendations, whitelist validation/editing, per-file batch cases, and background GUI batch scanning. The suite is now **39 tests passing**. See `docs/FEATURE_REGISTRY.md` and `docs/ORCHESTRATION.md` for the current implementation; the analysis below remains the historical baseline.

**ThePhish inspected:** `C:\Users\boser\Downloads\ThePhish-master` (see `analysis/THEPHISH_*` docs). ThePhish is AGPL-3.0 and service-coupled (IMAP/TheHive/Cortex/MISP/responders).

## 1. Architecture and workflow comparison

| Area | ThePhish (actual) | PhishGuard (current) | Gap / action |
|---|---|---|---|
| Primary workflow | Forward EML to monitored mailbox → analyst selects in web UI → case/analyzer pipeline runs | Paste Gmail “Show original”/raw text or scan `.eml` via CLI/GUI; local immediate analysis | Different ingestion UX; PhishGuard lacks mailbox-driven triage queue |
| Core architecture | Flask + Socket.IO app orchestrating external SOC services | Local Python library + Tkinter GUI + CLI; stdlib-first | PhishGuard is standalone/offline-first (strength) but lacks modular orchestration/integration layers |
| Data model | TheHive cases/tasks/observables as system of record | `ParsedEmail`, `ScanResult/Finding`, JSON/HTML reports, local GUI history | No investigation/case/evidence/timeline domain model |
| Extensibility | Analyzer execution delegated to Cortex ecosystem | Heuristic rules + embedded ML in-process | No analyzer registry/provider abstraction |

## 2. Capability matrix

| Capability | ThePhish | PhishGuard | Required action |
|---|---|---|---|
| IMAP ingestion / mailbox monitoring | **Yes**: list UNSEEN, fetch selected UID, EML extraction (`list_emails.py`, `case_from_email.py`) | **No** native IMAP client/monitoring | **Optional adapter (future)**: provider-independent IMAP ingestion module, read-only/safe defaults, no dependency for core scans |
| EML/raw parsing | **Partial/specialized**: parses forwarded internal EML attachment; MIME walk, header/body/attachment/hash extraction | **Yes**: `parse_email_text/file` for raw/RFC822 and simple headers, MIME body/attachments, auth header capture, size guard | **Improve**: richer MIME tree, all Received/auth chains, better encoding/HTML handling, evidence hashing, provenance |
| IOC/observable extraction | **Yes**: `ioc_finder` URLs/domains/IPs/emails from selected headers/body; unshortened URL expansion via analyzer | **Yes**: URLs/domains/IPs/emails/attachments, defang/normalization, Unicode/homograph/lookalike checks in scanner | **Improve**: unify observable model (types, normalization, dedup, provenance, confidence), add IPv6/hashes/content indicators |
| Whitelisting | **Yes**: exact/regex + domains-in-subdomains/URLs/emails; applied before observable creation and for unshortened URL | **Yes**: `whitelist.py` loads PhishGuard and ThePhish-compatible schemas; integrated in scanning flow | **Improve**: schema validation, match explainability, safe regex constraints, scoped whitelist decisions in results |
| Analyzer orchestration | **Yes (external)**: Cortex analyzer discovery/dispatch, rate-limit retries, job polling, special handlers | **No external orchestration**; fixed in-process heuristic + embedded NB ML | **Build**: local analyzer registry/dispatcher/job manager/result collector with optional external providers |
| Severity normalization | **Yes**: taxonomy extraction tweaks + configurable `analyzers_level_conf.json` mapping | **Implicit/local**: heuristic finding severities/categories and 0–100 score/verdict + ML label/confidence | **Improve**: explicit normalization layer (`safe/suspicious/malicious/informational/unknown/error`) and correlation across analyzers |
| Verdict calculation | **Yes**: count-based (any malicious observable => Malicious; else suspicious => Suspicious; else Safe), marks IOCs | **Yes**: explainable weighted heuristic scoring with verdict bands + reasons/findings + ML signal | **Improve**: correlate multi-source evidence/confidence, handle unknown/missing results as non-safe when appropriate, preserve rationale |
| TheHive integration | **Yes**: template/case/observable/task creation/updates/closure | **No** | **Optional adapter**: export/mapping interfaces only; never required for local operation |
| Cortex integration | **Yes**: analyzer execution, jobs/reports, responder jobs | **No** | **Optional adapter**: generic remote-analyzer provider behind local contracts |
| MISP integration | **Yes**: export case on malicious verdict; analyzer ecosystem support | **No** | **Optional adapter**: explicit IOC/case export with user control and redaction |
| Real-time progress | **Yes**: Socket.IO log stream to browser during blocking analysis | **Partial**: GUI status/log panels and progress cues; CLI output; no event bus | **Improve**: structured progress/events for long scans, batch jobs, and future async providers |
| Case management / investigation workflow | **Yes (external/TheHive-centric)**: tasks, case resolution states, analyst follow-up for suspicious | **No formal case workflow**; scan history and exports | **Build**: internal investigation/case/evidence/timeline models and analyst decision capture |
| Notifications | **Yes**: Mailer responder start/verdict emails | **No** | **Optional adapter** (low priority): user-controlled notifications with safe templates |
| Evidence integrity / provenance | **Partial**: EML/attachments/hashes/observables stored in TheHive; no app-side chain-of-custody model | **Partial**: raw input processed locally; reports include findings/observables; hashing/provenance model limited | **Improve**: preserve original evidence, compute/store hashes, record extraction/analysis provenance and timestamps |
| Configuration and rule engine | **Yes**: integration/case/whitelist/analyzer-level JSON configs | **Yes**: whitelist JSON, CLI options, embedded/default behavior; no analyzer-level external mapping engine | **Improve**: typed config schema/validation, profiles, explainable rule packs/mappings |
| Web/API service | **Yes**: Flask routes + Socket.IO (unauthenticated in code) | **No web service** (GUI/CLI/local) | **Decide carefully**: not required; if added later must include auth/CSRF/secure defaults |
| Deployment | **Docker stack** with multiple SOC dependencies | **Local Python run** (`python main.py`/`cli.py`), minimal deps | Keep PhishGuard simple/local; document optional integrations separately |

## 3. What PhishGuard already does better

- **Local/offline-first and safe-by-default:** no mandatory external services, no attachment execution, no automatic URL browsing, no default third-party uploads.
- **Gmail “Show original” UX:** paste/scan workflow, one-click Paste & Scan, practical for individual/analyst triage.
- **Explainable local detection:** transparent heuristic findings, category/risk breakdown, recommendations, and explicit limitation that auth results are header claims.
- **Evasion-aware parsing/scoring:** defanged URL normalization, dangerous schemes, Unicode/punycode/confusable/zero-width indicators, lookalike/typosquat, hidden-content/header anomaly signals (per README/tests/history).
- **Embedded ML (stdlib):** explainable NB signal without external model services or extra dependencies.
- **Performance/ergonomics:** precompiled patterns, batch scanning, parallel CLI `--jobs`, GUI/CLI/JSON/HTML reports, history/export.
- **Tested baseline:** existing unit/integration coverage (14/14) and sample fixtures.

## 4. What ThePhish does that PhishGuard does not

- IMAP mailbox ingestion and forwarded-EML case intake.
- Multi-analyzer execution against Cortex with job lifecycle, rate-limit handling, and per-analyzer report normalization.
- TheHive-native case/task/observable workflow and automated resolution/escalation behavior.
- MISP export and responder-based email notifications.
- Realtime web progress stream tied to backend analysis (albeit minimal/unauthenticated).

## 5. What both projects implement (differently)

- **Parsing/MIME handling:** both parse emails and attachments, but with different entry modes and depth.
- **Observable/IOC extraction:** both extract indicators; ThePhish via `ioc_finder` + external analyzer expansion, PhishGuard via local extraction/normalization.
- **Whitelisting:** both support allowlisting concepts; PhishGuard already accepts ThePhish-compatible schema.
- **Verdicting/reporting:** both produce final classifications, but ThePhish is external-report/count driven while PhishGuard is local heuristic/score/ML explainable.
- **Realtime/user feedback:** ThePhish web logs vs PhishGuard GUI/CLI progress/logging.

## 6. Architectural improvements to adopt (independently)

- **Modular core:** separate ingestion, parsing, observable extraction/normalization, analyzers, orchestration, normalization/correlation, verdict, case/evidence, reporting, and adapters.
- **Analyzer contracts:** typed inputs/outputs, supported observable types, timeouts, provenance, and error/unknown states.
- **Orchestration engine:** deterministic job manager with bounded concurrency, retries/backoff, cancellation, and structured events.
- **Verdict engine:** correlate local + optional provider findings with confidence/evidence; never treat missing/error results as safe.
- **Investigation model:** scan/investigation IDs, evidence hashes, timelines, analyst notes/overrides distinct from automated verdict.
- **Secure config/adapters:** optional integrations, explicit enablement, secret handling, validation, and no impact on local-only mode.

## 7. Should remain independent / optional

- **Remain independent:** local parser/scanner/ML/reporting/CLI/GUI core, offline operation, and existing public API behavior (`scan_email`, `scan_email_file`).
- **Optional/external-only:** IMAP polling services, TheHive, Cortex, MISP, responder/email gateways, web SOC dashboard requiring server infra.
- **Licensing boundary:** ThePhish source is AGPL-3.0; implement inspired functionality originally in PhishGuard (MIT) and avoid copying AGPL code.

## 8. Prioritized gap closure

1. **Foundation:** observable/evidence/result models, normalization, provenance/hashing, config validation.
2. **Orchestration/verdict:** local analyzer registry/dispatcher, correlation and explainable verdict improvements, unknown/error semantics.
3. **Investigation workflow:** case/timeline/reporting artifacts and CLI/GUI presentation.
4. **Optional adapters:** provider interfaces + mocked implementations/tests (IMAP/TheHive/Cortex/MISP stubs) without runtime dependency.
5. **Quality/security:** comprehensive tests, docs, and regression validation. 
