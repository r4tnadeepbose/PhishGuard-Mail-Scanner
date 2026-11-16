# Integrations

## 1. Policy

PhishGuard’s core scanning, reporting, GUI, and CLI operate **locally and offline-first**. External integrations are optional, disabled by default, and must not be required for normal scans.

Safety defaults:
- no third-party uploads by default
- no automatic browsing/fetching of suspicious URLs as part of detection
- no attachment execution
- no hardcoded credentials; secrets must be supplied securely and redacted from logs/reports

## 2. Current integration points

| Integration | Status | Notes |
|---|---|---|
| File/paste/CLI/GUI input | **Built-in** | Local raw source, `.eml`/text files, stdin, batch paths |
| Whitelist configuration | **Built-in** | JSON whitelist loading, validation, and editing (`phishguard.whitelist`), including ThePhish-compatible schema support |
| JSON/HTML export | **Built-in** | Local single and batch report generation/export |
| Investigation case export | **Built-in (local)** | `LocalCaseExportProvider` writes case JSON through `DEFAULT_REGISTRY`; no network access |
| Embedded ML model | **Built-in (local)** | Stdlib Naive Bayes bundled in-process (`phishguard.ml_model`); can be disabled per scan |
| Provider registry | **Built-in** | `phishguard.integrations.registry` registers the local case exporter and the safe null provider |
| External adapters (IMAP/TheHive/Cortex/MISP/notifications) | **Not implemented** | Planned, opt-in only; disabled by default |

The local provider is intentionally minimal but fully functional: the GUI’s **Save Case** action, CLI `--case`, CLI `--case-dir`, and GUI **Export Cases** all call the same `IntegrationProvider.run()` contract. This keeps future providers compatible with the existing code path.

## 3. Provider contract (implemented)

`phishguard/integrations/base.py` defines:
- `IntegrationCapability`: `provider_id`, `name`, `kind` (ingestion/analyzer/case/export/notification), supported types, `local_only`, `requires_network`, description
- `IntegrationResult`: provider ID, status (`disabled`, `ready`, `succeeded`, `failed`, `unknown`, `skipped`), summary, structured data/raw output, errors
- `IntegrationProvider`: `is_configured()` and `run(payload)`

`phishguard/integrations/registry.py` registers providers and exposes `DEFAULT_REGISTRY.export_case(case_dict, path)`. Provider failures return structured failed/disabled results and never mark a scan as safe. Runtime behavior: providers are selected explicitly, results carry status/data/errors, and no provider runs automatically during scanning.

## 4. Planned optional adapters (ThePhish-inspired, independent)

These adapters map concepts observed in ThePhish to PhishGuard’s own interfaces. They should be implemented independently (no AGPL code reuse) and registered through analyzer/orchestration/provider contracts.

| Adapter | Purpose | Typical external system | Mode | Key considerations |
|---|---|---|---|---|
| IMAP ingestion | Pull messages/EML submissions from a mailbox for triage | IMAP server | Optional, opt-in | Read-only defaults, folder/UID scoping, rate/size limits, TLS, credential secrecy, dedup/idempotency |
| TheHive case adapter | Create/update cases, tasks, observables from investigations | TheHive | Optional, opt-in | Field mapping, PII handling, TLS/auth, explicit export actions, failure isolation |
| Cortex analyzer adapter | Submit observables and collect analyzer reports/jobs | Cortex | Optional, opt-in | Timeouts/polling budgets, rate limits, result normalization, provenance, cost/privacy of queries |
| MISP export adapter | Export confirmed IOCs/case artifacts | MISP | Optional, opt-in | Analyst confirmation gates, attribute selection/redaction, confidence/tags, audit trail |
| Notification adapter | Send analyst/user notifications (e.g. verdict/start) | SMTP/mail gateway/webhook | Optional, opt-in | Template safety, recipient validation, sensitive-content minimization, disabled by default |

## 5. Security, privacy, and compliance

- **Least privilege:** use scoped API keys/accounts and read-only access where possible.
- **Transport security:** require TLS verification for non-local services.
- **Data minimization:** send only necessary observables/fields; support redaction and allowlists for export.
- **Auditability:** log integration actions/results locally with correlation/investigation IDs.
- **Licensing:** ThePhish is AGPL-3.0 (studied). Do not copy its code into PhishGuard; keep adapter implementations original and review all third-party dependency licenses.

## 6. Configuration

Integration configuration should be isolated from core scan defaults (e.g. dedicated config file/profile or environment-backed settings), validated before use, and safe when absent. See `docs/CONFIGURATION.md`. 
