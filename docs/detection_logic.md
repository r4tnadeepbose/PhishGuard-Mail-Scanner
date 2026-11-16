# PhishGuard Detection Logic

PhishGuard uses weighted heuristic signals to estimate phishing risk. It is designed to be transparent and easy to extend.

## 1. Input Parsing
- Parses `.eml`/header-style text when possible (From, Reply-To, Subject, Date, body).
- Falls back to plain-text scanning when headers are unavailable.
- Extracts URLs using a regex-based matcher.

## 2. Signal Categories & Example Weights

### Sender/Header Signals
| Signal | Example | Weight |
|---|---|---|
| Reply-To domain differs from From domain | `@company.com` vs `@attacker.top` | +12 |
| Unusual sender format | Missing clear email address | +6 |
| Possible display-name impersonation | "Microsoft Support" from unrelated domain | +8 |
| Limited header information | Body-only analysis | +2 |

### URL Signals
| Signal | Example | Weight |
|---|---|---|
| Raw IP host | `http://192.168.1.10/login` | +10 |
| Deceptive `@` in URL | `https://trusted.com@evil.top` | +10 |
| Punycode/lookalike host | `xn--...` domains | +9 |
| Suspicious TLD | `.zip`, `.top`, `.xyz`, etc. | +6 |
| Complex/long host | Excessive subdomains or long hostname | +5 |
| Insecure HTTP link | `http://...` | +3 |
| Many links | >= 5 URLs in message | +5 |

### Content Signals
| Signal | Example | Weight |
|---|---|---|
| Credential/sensitive-info request | "verify password", "confirm identity" | +12 |
| Payment/prize lure | gift cards, wire transfer, refund/prize | +10 |
| Urgency/pressure language | "act now", "account suspended" | +8 |
| Risky attachment indicators | `.html`, `.exe`, "enable content" mentions | +7 |
| Generic greeting | "Dear Customer" | +3 |
| Link + credential combo | URL present with verification request | +6 |

## 3. Verdict Thresholds
- **0–14**: Low Risk
- **15–29**: Medium Risk
- **30–49**: High Risk
- **50+**: Critical Risk

### Header/Transport & Auth Signals (implemented)
| Signal | Example | Weight |
|---|---|---|
| Return-Path domain mismatch | envelope sender differs from From | +6 |
| SPF fail/softfail/error (from `Authentication-Results`/`Received-SPF`) | `spf=fail` | +10 / +6 |
| DKIM fail/softfail/error | `dkim=fail` | +10 / +6 |
| DMARC fail/softfail/error | `dmarc=fail` | +10 / +6 |
| SPF/DKIM/DMARC = none | missing alignment/config | +2 |
| Risky attachment type (metadata filename) | `.exe`, `.html`, `.js`, etc. | +10 |
| Double-extension attachment name | `invoice.pdf.exe` | +6 |
| Many Received hops | >= 8 hops | +2 |
| Missing Received chain (when headers exist) | pasted/export artifacts | +1 |

## 4. Additional Capabilities (including ThePhish-inspired additions)
- **Observable extraction**: URLs, email addresses, IPs, and domains are extracted and included in results/reports.
- **Whitelist filtering**: optional whitelist (`exact`, `regex`, trusted domains for URLs/emails) can suppress known-safe observables from risky URL scoring (concept adapted from ThePhish's whitelist model).
- **Batch scanning**: scan directories of `.eml/.txt/.mail` files via CLI `--dir`
- **Report export**: JSON and HTML report generation for single scans; JSON batch reports
- **Metadata extraction**: subject/from/reply-to/return-path/date/message-id, hop count, attachments, URL counts
- **Auth result parsing**: extracts `Authentication-Results`, `ARC-Authentication-Results`, `Received-SPF` indicators

## 5. Known Limitations
- Parses SPF/DKIM/DMARC results from headers but does not perform live DNS validation.
- No attachment sandboxing or binary content inspection.
- No external reputation/threat-intel lookups by default.
- Regex/keyword heuristics may miss novel attacks or flag benign messages.

## 6. Extension Ideas
- Add URL reputation checks (e.g. VirusTotal/PhishTank/Safe Browsing APIs).
- Perform live DNS SPF/DKIM/DMARC and BIMI verification.
- Add domain age/lookalike (typosquatting) detection.
- Introduce ML/NLP scoring and combine with heuristic score.
- Add mailbox ingestion (IMAP) and analyst workflow integrations.
