# Configuration

## 1. Overview

PhishGuard is designed to run with safe local defaults and minimal required configuration. Core scanning does not require network services, API keys, or external databases.

## 2. Current configuration options

### 2.1 CLI (`cli.py`)

| Option | Purpose | Default |
|---|---|---|
| `--file <path>` | Scan one `.eml`/text file | — |
| `--text <raw>` | Scan raw email text passed inline | — |
| `--stdin` | Read raw email content from stdin | — |
| `--dir <path>` | Scan all `.eml`/`.txt`/`.mail` files in a folder | — |
| `--whitelist <path>` | Load and validate whitelist JSON (PhishGuard or ThePhish-compatible schema) | none |
| `--use-default-whitelist` | Use project-root `whitelist.json` when present | off |
| `--json <path>` | Write JSON report (single) or batch JSON report (`--dir`) | off |
| `--html <path>` | Write HTML report (single) or batch HTML index (`--dir`) | off |
| `--case <path>` | Write one investigation case JSON (single-file mode) | off |
| `--case-dir <path>` | Write one investigation case JSON per scanned file (`--dir` mode) | off |
| `--jobs <n>` | Parallel workers for `--dir` scans (`0`=auto, `1`=sequential) | `0` (auto) |
| `--no-ml` | Disable the embedded ML signal for this scan | ML enabled |
| `--quiet` | Suppress normal console output except errors | off |
| `--cvss-vector <vector>` | Calculate and print a CVSS v3.1 base score from a vector, then exit (no scan input required) | — |
| `--version` | Print version and exit | — |

> Run `python cli.py --help` for the authoritative, version-specific option list. Exit code is `1` when any scanned result scores `>= 20` (Suspicious or worse), otherwise `0`; configuration/validation errors exit `2`.

### 2.2 GUI (`gui.py`)

- Dashboard layout: branded sidebar, quick-action toolbar, scanned-message inbox, reading pane, and tabbed analysis views.
- Paste raw source / Gmail “Show original” content and run **Scan Now** or **Paste & Scan**; the raw editor lives in the **Source** tab.
- **ML signal** checkbox toggles the embedded model for subsequent scans.
- Configure/select/reload/clear whitelist from the sidebar; invalid files are reported and block use.
- Add the selected observable to the active whitelist as an exact rule, with optional immediate rescan.
- Investigation case panel records analyst verdict/notes and exports case JSON through the local provider.
- Batch Scan runs in a background thread with progress and cancellation; double-click a row to load it. Export batch JSON, batch HTML, or one case per file.
- Session History supports reload/delete/clear and JSON preview; export the selected/last result as JSON, HTML, or case JSON.
- View verdict/score (with risk gauge), findings, observables, auth claims, ML/category breakdown, and details.
- Keyboard shortcuts: `Ctrl+O` open, `Ctrl+S` save source, `Ctrl+Enter` scan, `Ctrl+Shift+V` paste & scan, `Ctrl+E` export JSON, `Ctrl+J` save case, `Ctrl+H`/`F1` help.

### 2.3 Whitelist (`whitelist.json`, `phishguard/whitelist.py`)

Supported schemas:
- **PhishGuard schema:** `exact`, `regex`, `trusted_domains_in_urls`, `trusted_domains_in_emails`.
- **ThePhish-compatible schema:** `exactMatching`, `regexMatching`, `domainsInURLs`, `domainsInEmails`, `domainsInSubdomains` (mapped by loader).

Example (PhishGuard schema):

```json
{
  "exact": {
    "domain": ["example.com"],
    "url": [],
    "email": ["alerts@example.com"],
    "ip": []
  },
  "regex": {
    "domain": [],
    "url": [],
    "email": [],
    "ip": []
  },
  "trusted_domains_in_urls": ["example.com"],
  "trusted_domains_in_emails": ["example.com"]
}
```

Guidance:
- Keep whitelists minimal and specific; over-broad domain/regex rules can suppress true positives.
- Prefer exact matches or narrowly scoped domain trust over complex regex.
- Treat whitelist matches as context in reports, not automatic proof of safety.

### 2.4 Parser/runtime safety limits

- `phishguard/parser.py` enforces `MAX_PARSE_BYTES` (default 5 MB) for file parsing and `MAX_INPUT_CHARS` (default 2,000,000) for raw text parsing to reduce memory/DoS risk.
- Inputs are treated as untrusted; malformed or oversized content fails with a clear error instead of crashing.

## 3. Planned/additive configuration (orchestration and integrations)

To support modular analyzers and optional adapters without breaking local use, future configuration should be typed and validated (example conceptual structure):

```yaml
scan:
  local_only: true
  max_input_bytes: 5242880
  enable_ml: true
analyzers:
  heuristic: { enabled: true, timeout_ms: 5000 }
  ml: { enabled: true, timeout_ms: 2000 }
whitelist:
  path: whitelist.json
integrations:
  imap:
    enabled: false
    host: ""
    folder: "INBOX"
    username_env: "PHISHGUARD_IMAP_USER"
    password_env: "PHISHGUARD_IMAP_PASSWORD"
    tls_verify: true
  thehive:
    enabled: false
    url: ""
    api_key_env: "PHISHGUARD_THEHIVE_API_KEY"
```

Rules for integration config:
- **Opt-in only:** all external integrations disabled unless explicitly enabled.
- **No secrets in files:** reference environment variables/secret stores; never log credentials or tokens.
- **Validation:** reject unknown fields where practical, enforce URL/TLS/timeout bounds, and fail closed for unsafe settings.
- **Isolation:** integration failures must not break local-only scanning.

## 4. Security recommendations

- Store configs with least-privilege file permissions; do not commit secrets.
- Review whitelist and analyzer-mapping changes as detection logic changes (test for false positives/negatives).
- For any future networked deployment/UI, add authentication, CSRF protection, and secure transport; do not expose unauthenticated control endpoints.
- Keep dependencies and runtime environments updated if external components are introduced. 
