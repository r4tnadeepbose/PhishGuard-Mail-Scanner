# PhishGuard Mail Scanner

PhishGuard is a local, explainable phishing-email triage tool for Windows/macOS/Linux. It is built for the **Gmail “Show original”** workflow: open an email → **⋮ → Show original → Copy to clipboard** → paste into PhishGuard → scan → get a full risk report.

> **Security note:** PhishGuard is a fast triage aid, not a replacement for secure email gateways, MFA, sandboxing, server-side authentication verification, or incident-response processes. **No scanner can detect every phishing email or be impossible to trick** (e.g. compromised legitimate accounts, perfect domain/auth alignment, novel obfuscation, or context-only social engineering can evade detection).

## What you get (full report)

Each scan produces a defense-in-depth report with:
- **Verdict, rating, and score (0–100):** `Low Risk` / `Suspicious` / `High Risk` / `Critical`
- **Summary and recommended actions** (context-aware)
- **ML/statistical analysis:** lightweight embedded Multinomial Naive Bayes label, phishing/legitimate likelihood, confidence, and top indicators (additional signal)
- **Category risk breakdown:** heuristic points by area (header/identity, authentication, URL, content, attachment, other)
- **Security assessment (local/offline):** evidence-linked **MITRE ATT&CK** technique hints, relevant **CWE** references, and an estimated triage **CVSS v3.1** score/vector for prioritization (not a confirmed software-vulnerability CVSS). CVEs are not auto-attributed from email content (product/version-specific); a CVSS v3.1 calculator is available via CLI.
- **Detailed findings:** severity, score contribution, title, detail, and reasoning where applicable
- **Authentication analysis:** SPF/DKIM/DMARC/Received-SPF parsed from headers (**header claims, not independently verified**)
- **Metadata:** subject, sender, reply-to, return-path, recipients, date, message-id, hops, attachments, URL counts
- **Observables:** extracted URLs, emails, IPs, domains (with whitelist-aware filtering) and active URLs
- **Investigation case:** every scan builds a local case with evidence hash, automated verdict, analyzer result, and timeline; analyst decision and notes can be recorded and exported
- **Exports:** JSON and HTML reports (single scan), JSON/HTML batch reports, and investigation case JSON (single or one per batch file)

## Core workflow

1. In Gmail, open the suspicious email → **⋮ (More)** → **Show original** → **Copy to clipboard**.
2. Run PhishGuard and click **Paste & Scan** (GUI) or paste and click **Scan Now**.
3. Review the verdict, score, ML likelihood, findings, recommended actions, auth/headers, observables, and export/share the report as needed.

## Key features

### Triage & UX
- **Dashboard-style GUI** (Tkinter): pale blue canvas, white cards, deep navy sidebar/header, navy accent buttons, branded sidebar, scanned-message inbox, reading pane with From/To/Date/Auth header, verdict stamp, warning banner, risk gauge, and parsed message body; tabs for Report, Details, Findings, Observables, Source, Activity, Batch Scan, History & Export, and Help
- **One-click Paste & Scan** in GUI for clipboard/raw-source workflow; raw source lives in a dedicated Source tab
- **Investigation case panel:** case ID, evidence hash/size, live timeline, analyst verdict (Confirm Phishing / Mark Benign / Clear Decision), analyst notes, and case JSON export
- **Session history:** reload, delete, or clear entries; JSON preview; export the selected/last result as JSON, HTML, or case JSON
- **Whitelist management:** choose/reload/clear a whitelist, validate it, and add the selected observable as an exact rule with optional immediate rescan
- **ML toggle:** the toolbar **ML signal** checkbox enables/disables the embedded model per scan
- Load/save/open `.eml`/`.txt`/`.mail`, sample loader, copy summary/findings/log, keyboard shortcuts
- CLI for `--file`, `--text`, `--stdin`, and `--dir` (batch), with `--case`, `--case-dir`, and `--no-ml`

### Detection & hardening (defense in depth)
- **Heuristic risk engine:** explainable 0–100 scoring with granular findings
- **Header/identity forensics:** From/Reply-To/Return-Path checks with related-domain awareness, display-name impersonation hints, freemail-role impersonation signals, Message-ID domain mismatch, sender anomalies, Received-hop context, empty-subject/limited-header signals
- **URL analysis & evasion resistance:** URL extraction with defanged/obfuscated normalization (`hxxp`, `[.]`, `[:]`, HTML entities), IP hosts, suspicious TLDs, complex/long hosts, deceptive `@` in authority, sensitive-action path/query cues, insecure HTTP, many-links signals, dangerous URI schemes (`javascript:`, `data:`, `file:`, `vbscript:`)
- **IDN/homograph & obfuscation signals:** punycode/IDN indicators, suspicious Unicode/confusable characters in domains/sender/display names, zero-width/bidi-control characters
- **Lookalike/typosquat hints:** lightweight similarity checks for sender/URL domains against common brand patterns (additional signal)
- **Content & lure detection:** urgency/pressure, credential harvesting, payment/prize/fraud lures, generic greetings, link+credential combinations
- **Attachment & HTML indicators:** risky file types and double-extension filenames from metadata, risky attachment mentions, active/hidden HTML patterns in raw source (script/form/iframe/base/meta, hidden/zero-opacity/font-size cues)
- **Authentication parsing:** SPF/DKIM/DMARC/Received-SPF indicators from message headers (reported as unverified claims)
- **Observable extraction & whitelist filtering:** URLs/emails/IPs/domains extracted for analysis; optional whitelist (`exact`/`regex`/trusted domains, PhishGuard + ThePhish-compatible schema) to reduce noise from known-safe observables

### ML, performance, and reporting
- **Lightweight ML (built-in):** embedded Naive Bayes text model (`phishguard/ml_model.py`, pure Python/stdlib, no external ML dependencies)
- **Fast local processing:** precompiled detection patterns and efficient parsing/scanning for typical email-sized inputs
- **Parallel batch scanning:** CLI `--jobs` for multi-core/CPU-utilized folder scans (`0`=auto, `1`=sequential, `>1` parallel workers); GUI batch scanning runs in a background thread with progress and safe cancellation
- **Reports:** rich console output, JSON/HTML single-scan export, JSON/HTML batch export, and local investigation case JSON
- **Security hardening:** safe input size limits for raw text/files, local-only analysis defaults, escaped report rendering, validated whitelist handling, and structured error handling for smooth CLI/batch flow
- **Provider registry:** local case export is wired through `phishguard.integrations.registry`; external adapters remain disabled by default

## Project structure

```text
PhishGuard-Mail-Scanner/
├─ phishguard/
│  ├─ __init__.py
│  ├─ parser.py         # Raw email/header/MIME parsing, auth extraction, safety limits
│  ├─ scanner.py        # Heuristic engine, hardened checks, observables, scoring/verdicts, recommendations
│  ├─ ml_model.py       # Lightweight embedded ML/statistical analysis
│  ├─ whitelist.py      # Whitelist loading/matching/validation/editing (PhishGuard & ThePhish-compatible)
│  ├─ investigation.py  # Evidence hashing, observables, analyzer results, case/timeline, analyst actions
│  ├─ threat_framework.py # MITRE ATT&CK/CWE mappings and CVSS v3.1 calculator/triage estimate
│  ├─ integrations/     # Provider contracts, registry, local case export, safe null providers
│  └─ report.py         # JSON/HTML single and batch report rendering
├─ samples/             # Example emails/fixtures (incl. Gmail "Show original" style)
├─ tests/               # Unit/integration tests
├─ docs/                # Detection logic, research, feature registry, roadmap, examples
├─ cli.py               # Command-line interface
├─ gui.py               # Tkinter desktop interface
├─ main.py              # GUI entry point
├─ whitelist.json       # Default whitelist rules (optional)
├─ requirements.txt
└─ README.md
```

## Requirements

- **Python 3.9+** (tested in this environment with Python 3.15)
- **Tkinter** for GUI (bundled with most standard Python installs on Windows/macOS; on some Linux distros install `python3-tk`)
- **No third-party packages required** for the core scanner/GUI/CLI/ML module (stdlib-first)

## Quick start

### Run the GUI

```powershell
cd "$HOME\Downloads\PhishGuard-Mail-Scanner"
python main.py
```

(or `python gui.py`)

### Scan a file (CLI)

```powershell
python cli.py --file samples\phishing_with_auth_fail.eml
python cli.py --file samples\linkedin_job_alert_show_original.eml --use-default-whitelist
```

### Scan from clipboard/stdin or raw text

```powershell
Get-Content email.eml -Raw | python cli.py --stdin --use-default-whitelist
python cli.py --text "Urgent: verify your account now at http://192.168.1.10/login"
```

### Export reports

```powershell
python cli.py --file samples\phishing_with_auth_fail.eml --json report.json --html report.html
python cli.py --file samples\phishing_with_auth_fail.eml --case case.json --no-ml
```

### CVSS v3.1 calculator (offline utility)

```powershell
python cli.py --cvss-vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

### Batch scan a folder (parallel/multi-core)

```powershell
# --jobs 0 = auto, --jobs 1 = sequential, --jobs N = N parallel workers
python cli.py --dir samples --json batch_report.json --html batch_report.html --case-dir cases --jobs 0
```

### Whitelist options

```powershell
python cli.py --file samples\phishing_with_auth_fail.eml --whitelist whitelist.json
python cli.py --file samples\phishing_with_auth_fail.eml --use-default-whitelist
```

## How it works (high level)

PhishGuard combines multiple independent signals into an explainable triage decision:
1. **Parse & normalize** raw source (headers/MIME/body), with safe size limits and deobfuscation-aware extraction for common URL evasion.
2. **Extract observables** (URLs/emails/IPs/domains) and apply optional whitelist filtering.
3. **Run hardened checks** across header/identity, authentication-header claims, URL/scheme/homograph/lookalike indicators, content lures, attachment/HTML/evasion patterns, and more.
4. **Score & classify** with a heuristic 0–100 verdict and category breakdown.
5. **Run lightweight ML analysis** (embedded Naive Bayes) as an additional explainable signal.
6. **Generate a full report** with findings, recommendations, and exportable artifacts.

Auth results (SPF/DKIM/DMARC) are treated as **informative header claims only**, not proof of authenticity or maliciousness.

## Limitations

- **Not foolproof:** heuristic/embedded-ML triage can produce false positives/negatives and cannot guarantee detection of every phishing attempt.
- **Header trust:** SPF/DKIM/DMARC values are parsed from message headers and are **not independently or cryptographically verified** by this tool.
- **No live enrichment by default:** no DNS validation, threat-intel lookups, mailbox-provider telemetry, sandbox detonation, or full browser rendering.
- **No active exploitation:** attachments are not executed and suspicious URLs are not automatically visited.
- **Scope:** best used for local, fast triage and education; validate suspicious messages via official/out-of-band channels and your organization’s security tooling.

## Safety principles

- Local/offline-first analysis of pasted or file-based email source
- No automatic opening of suspicious links or execution of attachments
- Transparent, explainable findings and conservative language around unverified signals
- Existing CLI/GUI workflows preserved while features are extended incrementally

## Testing

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

## Roadmap / docs

### Documentation
- `docs/ARCHITECTURE.md` - current and target architecture
- `docs/ORCHESTRATION.md` - analyzer/job/normalization/verdict design (incremental)
- `docs/DETECTION_METHODOLOGY.md` - signals, scoring, normalization, limitations
- `docs/INTEGRATIONS.md` - optional adapters and safety constraints
- `docs/CONFIGURATION.md` - CLI/GUI/whitelist and planned config model
- `docs/TESTING.md` - test strategy and commands
- `docs/detection_logic.md`, `docs/FEATURE_REGISTRY.md`, `docs/IMPLEMENTATION_ROADMAP.md`, `docs/RESEARCH_AND_COMPETITOR_ANALYSIS.md`

### ThePhish reverse-engineering (source studied: AGPL-3.0; PhishGuard changes implemented independently)
- `analysis/THEPHISH_ARCHITECTURE.md`
- `analysis/THEPHISH_EXECUTION_FLOW.md`
- `analysis/THEPHISH_DATA_FLOW.md`
- `analysis/THEPHISH_INTEGRATION_MAP.md`
- `analysis/THEPHISH_FEATURE_REGISTRY.md`
- `analysis/THEPHISH_SECURITY_AUDIT.md`
- `analysis/PHISHGUARD_GAP_ANALYSIS.md`
- `analysis/PHISHGUARD_IMPLEMENTATION_ROADMAP.md`
- `analysis/LICENSING_AND_ATTRIBUTION.md`

### Example artifacts
- `docs/examples/example_scan_report.json` / `.html` - real report generated from a sample scan
- `docs/examples/example_batch_report.html` - real batch HTML report generated from `samples/`
- `docs/examples/example_investigation_case.json` - investigation/case-evidence-timeline example from a local scan result

### Additive modules (ThePhish-inspired, original implementation)
- `phishguard/investigation.py` - evidence hashing/provenance, observable normalization/dedup, normalized analyzer results, investigation case/timeline models, analyst verdict/notes
- `phishguard/integrations/` - provider-agnostic contracts, null provider, and a functional local case JSON export provider registered in `DEFAULT_REGISTRY`; external adapters remain disabled by default

## License

This project is licensed under the [MIT License](LICENSE). See `LICENSE` for details. Provided for educational/defensive use.
