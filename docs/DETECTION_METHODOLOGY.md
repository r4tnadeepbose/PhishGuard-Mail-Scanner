# Detection Methodology

## 1. Principles

PhishGuard uses **defense-in-depth, explainable triage**: multiple independent signals are extracted from an email and correlated into a risk score and verdict. The goal is practical analyst support with low friction, not a claim of perfect detection.

- **Local-first:** core detection runs locally without external lookups by default.
- **Transparent:** findings include category, severity, evidence, and explanation.
- **Evidence-aware:** missing, failed, or unknown signals are tracked explicitly and do not count as proof of safety.
- **Safe handling:** suspicious URLs/attachments are analyzed as data; they are never executed or auto-opened.

## 2. Analysis pipeline

1. **Input acquisition:** paste raw source, `.eml`, text file, or batch inputs.
2. **Parsing:** extract headers, body/MIME parts, attachments metadata, received/auth-related fields, and raw content.
3. **Normalization & observable extraction:** URLs, domains, IPs, emails, hashes/identifiers (as available), attachment indicators; defang/Unicode normalization and provenance.
4. **Whitelisting/context:** apply configured allowlists and record matches as context (not automatic benign verdict).
5. **Analysis:** run heuristic analyzers and embedded ML.
6. **Correlation & verdict:** aggregate weighted evidence into score/verdict with reasons and recommendations.
7. **Reporting:** present GUI/CLI/JSON/HTML outputs and investigation artifacts.

## 3. Signal categories

| Category | Examples of signals | Intent |
|---|---|---|
| Authentication (header claims) | SPF/DKIM/DMARC/ARC/Received-SPF presence and stated results | Surface sender-auth context; **not cryptographically verified** by PhishGuard |
| Identity & headers | From/Reply-To/Return-Path alignment, Message-ID/domain anomalies, received-chain anomalies, suspicious routing patterns | Detect spoofing/impersonation and tampering indicators |
| URLs & domains | Defanged/obfuscated URLs, dangerous schemes, punycode/IDN, confusable/homograph chars, lookalike/typosquat domains, mismatched display/link context | Detect lure/redirection and brand impersonation infrastructure |
| Content/language | Credential/payment/urgency lures, coercion, social-engineering patterns, suspicious instructions | Detect phishing intent in message body/subject |
| HTML/content evasions | Hidden/invisible text, obfuscated markup/scripts/forms indicators, tracking/pixel-like artifacts (where detected) | Detect cloaking and user-deception techniques |
| Attachments | Risky extensions/types, double extensions, archive/macro indicators, suspicious naming | Detect payload-delivery risk without executing files |
| ML/statistical signal | Embedded Multinomial Naive Bayes likelihood/confidence and top indicators | Provide an additional explainable probabilistic signal |
| Optional external intel (future/adapters) | Analyzer/reputation/case-intel results from configured providers | Enrich local verdict when explicitly enabled |

## 4. Scoring and verdicts

PhishGuard’s heuristic engine assigns weighted risk contributions per finding and combines them into a bounded score (current implementation: **0–100**). The embedded ML model is reported as a companion signal (label, phishing likelihood, confidence, indicators) and may influence interpretation/correlation in future orchestration.

| Score range | Verdict | Interpretation |
|---|---:|---|
| 0–19 | **Low Risk** | Few or low-severity phishing indicators observed |
| 20–39 | **Suspicious** | Some concerning signals; verify before interacting |
| 40–69 | **High Risk** | Multiple/strong indicators; likely phishing or unsafe |
| 70–100 | **Critical** | Severe, high-confidence phishing/malware-delivery indicators |

> Verdict bands are heuristic and explainable; analysts should use full findings, evidence, and context for final decisions.

## 5. Normalization (target for multi-analyzer/orchestrated mode)

When multiple analyzers/providers are used, raw outputs are normalized to a common scale while preserving originals:

- `informational` — contextual data, no direct risk assertion
- `safe` — evidence supporting benign classification
- `suspicious` — weak/moderate malicious indicators
- `malicious` — strong malicious indicators
- `unknown` — insufficient data
- `error` — analyzer/parsing/provider failure

Correlation must consider confidence, source reliability, observable provenance, and conflicts. `unknown/error` outcomes create evidence gaps and must not be treated as `safe`.

## 6. Explainability and reporting

Every scan/report should aim to include:
- verdict, score/risk, and confidence/rationale
- categorized findings with severity and evidence
- extracted observables and whitelist/context decisions
- authentication header-claim summary (unverified)
- ML analysis summary and indicators
- recommended actions and limitations
- investigation metadata (IDs, hashes, timestamps/provenance) as available

## 7. Limitations and safe-use guidance

- No automated detector can guarantee detection of all phishing; novel/evasive attacks may evade heuristics/ML.
- Header authentication fields can be forged/misinterpreted and are reported as claims unless independently verified.
- A “Low Risk” result does not prove legitimacy; a “High/Critical” result warrants caution even if some signals appear benign.
- Users should independently verify unexpected requests, avoid entering credentials from email links, and treat attachments/URLs as potentially harmful.
- External enrichment/integrations (if enabled) may have privacy, availability, and trust implications and must remain opt-in. 
