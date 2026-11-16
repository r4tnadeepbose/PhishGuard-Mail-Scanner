# Research and Competitor Analysis (Phase 0)

**Project:** PhishGuard Ultimate (evolved from PhishGuard Mail Scanner)  
**Date:** 2026-11-16  
**Method:** Repository inspection, local source review (including `ThePhish-master.zip` previously analyzed), and knowledge-based survey of widely referenced open-source email/security projects and standards. External web search tooling in this environment returned limited/no results during this pass; therefore this document focuses on **well-known, publicly documented capabilities/architectures** and explicitly marks items requiring deeper source-level validation as follow-up.

> **Licensing/copyright note:** No third-party source code, proprietary logic, branding, or copyrighted assets were copied. Any future reuse must follow each project's license and attribution requirements.

## 1. Reference projects & platforms (capability-oriented)

| Project/Platform | Category | Architecture (high-level) | Notable capabilities | Typical integrations/deps (examples) | Testing/ops notes | Gaps vs current PhishGuard | Feasibility for PhishGuard |
|---|---|---|---|---|---|---|---|
| **ThePhish** (emalderson/ThePhish) | Email phishing analysis automation | Python/Flask app; IMAP intake, parsing/IOC extraction, whitelist; integrates with **TheHive, Cortex, MISP** for case/analysis/export workflows | EML parsing, observable extraction (URL/domain/IP/email/hash/attachment), whitelisting, analyst workflow, verdict/case handling, MISP export via platform | TheHive/Cortex/MISP APIs, mail server, analyzers/responders | Depends on external platform stack; operational complexity | Automated platform-backed case mgmt, analyzer ecosystem, MISP export | **Partial now** (whitelist/observable concepts adapted). **Deferred** for full stack without infra/APIs |
| **Apache SpamAssassin** | Anti-spam/phishing filtering | Rule-based scoring engine with plugins; header/body/URI/Bayes/DNS checks | Large rule corpus, Bayesian filtering, DNSBL/URI checks, plugin architecture, tunable scores | Perl ecosystem, DNS/network lookups, optional Bayes DB | Mature regression test culture in distro; config-heavy | Extensive rule packs, Bayesian learning, mature DNSBL ecosystem | **Conceptual inspiration** for rule plugins/scoring; full parity **deferred** |
| **Rspamd** | Spam/phishing filtering | Modular C/Lua rules, statistical modules, async scanning | Heuristics + statistical classifiers, fuzzy hashes, DKIM/SPF/DMARC handling, fast daemon | Redis, DNS, maps, Lua modules | Production-grade but infra-heavy | Daemon architecture, fuzzy/statistical modules | **Partial** (heuristics/auth parsing); daemon/statistical **deferred** |
| **MISP** | Threat intelligence sharing | Web platform + APIs; events/attributes/tags/galaxies | IOC sharing, correlation, feeds, export formats | DB, workers, API keys, feeds | Requires instance ops | Native IOC sharing/correlation platform | **Deferred** (needs instance); export adapters possible later |
| **OpenCTI** | Threat intelligence platform | Graph-based knowledge platform with connectors | STIX-oriented modeling, relationships, enrichment connectors | Graph DB/services, connectors | Heavy deployment | Graph CTI, STIX-native workflows | **Deferred** |
| **TheHive / Cortex** | Case mgmt / observable analysis | Case/alert platform + analyzer/responder engine | Cases/tasks/observables, analyzer jobs, responders | Elasticsearch/Cassandra (TheHive), analyzers, APIs | Infra-dependent | Enterprise case pipeline, analyzer ecosystem | **Deferred** |
| **URLhaus / PhishTank / OpenPhish / AbuseIPDB / AlienVault OTX** | Reputation/feeds | Web APIs/feeds | URL/domain/IP/hash reputation, community intel | API keys/rate limits, network | Data freshness/ToS dependent | Live reputation enrichment | **Deferred/opt-in adapters** (no keys/consent in baseline) |
| **VirusTotal / MalwareBazaar** | Malware/IOC reputation | Cloud APIs | Hash/URL/file reputation, metadata | API keys, quotas, privacy considerations | Must not upload sensitive data without consent | External reputation, sandbox reports | **Deferred/opt-in** |
| **YARA** | Pattern matching | Rule engine/library | Signature/pattern matching for files/memory/text | Rulesets, yara-python/native | Rule quality dependent | Attachment/content signature scanning | **P2/P3** (optional local integration) |
| **ClamAV / oletools / pefile** | Malware/static analysis | Scanners/parsers | AV signatures, Office macro/OLE analysis, PE parsing | Engines/libs, updates | False positives/perf tradeoffs | Deep attachment triage | **P2/P3** optional |
| **Mail header analyzers (various)** | Forensics UX | Web/CLI tools parsing Received/auth headers | Hop/source visualization, auth interpretation | Minimal | Often header-claim focused | Rich forensic visualizations, trust-boundary clarity | **P1** incremental UX/reporting improvements |
| **MTA-STS/TLS-RPT/BIMI/DNS tools** | Auth/transport posture | DNS/HTTP policy checks | Domain security posture signals | DNS/network | External verification required | Independent verification & posture modules | **P2** with careful network/timeout controls |

## 2. Standards/specifications reviewed (for planned design)
- **RFC 5322** (Internet Message Format), **RFC 6376** (DKIM), **RFC 7208** (SPF), **RFC 7489** (DMARC), **RFC 8617** (ARC), **RFC 8461** (MTA-STS), **RFC 8460** (TLS-RPT), **RFC 9460** (SVCB/HTTPS DNS) — relevant to parsing, authentication, and transport/security posture. Full cryptographic/DNS verification not yet implemented; current engine parses **header claims** only and explicitly warns they are unverified.

## 3. Feature comparison matrix (current vs target direction)

| Capability area | Current PhishGuard (baseline after recent fixes) | Typical in advanced tools/platforms | Status |
|---|---:|---:|---|
| EML/header parsing & metadata | Yes (stdlib, heuristic + RFC822) | Deep MIME/edge-case forensics | **Implemented (basic)** |
| Observable extraction (URL/email/IP/domain) | Yes | Rich IOC normalization/relationships | **Implemented (basic)** |
| Whitelist filtering | Yes (exact/regex/trusted domains) | Context-aware allow/deny workflows | **Implemented (basic)** |
| SPF/DKIM/DMARC **header-claim** parsing | Yes, with unverified caveat | Independent DNS/crypto verification | **Implemented (claims)** / **Deferred (verified)** |
| URL/content/phishing heuristics | Yes (explainable findings, 0–100 calibrated) | Large rule packs, ML, sandboxing | **Implemented (heuristic)** |
| Attachment triage | Filename/type/double-ext/text hints | Hashing, YARA/AV, macro/PDF/static analysis | **Partial** |
| Batch scan + JSON/HTML reports | Yes (CLI/GUI, parallel CLI `--jobs`) | Case mgmt, STIX/PDF, timelines | **Implemented (basic)** |
| Threat intel enrichment (VT/URLhaus/etc.) | No (no network/API by default) | Multi-provider enrichment/caching | **Planned/Deferred (opt-in)** |
| Case management / forensics chain-of-custody | Local case JSON + evidence SHA-256/timeline; no database | TheHive-like workflows, evidence integrity | **Implemented (local export)** / **Deferred (DB/infra)** |
| AI assistant / ML pipeline | No | LLM summaries, trained classifiers | **Deferred (optional, gated)** |
| REST API / SIEM-SOAR adapters | No | Automation/integration surfaces | **Deferred** |
| ATT&CK/STIX mapping/graph viz | No | Evidence-linked mappings/exports | **Deferred** |

## 4. Key takeaways for PhishGuard Ultimate
1. **Preserve strengths:** transparent local heuristics, stdlib-first core, explainable findings, CLI/GUI parity, safe defaults (no URL detonation, no attachment execution).
2. **Highest-value next steps (P0/P1):** stronger parsing/validation, better auth trust-boundary messaging, richer IOC normalization, modular rule/detection interfaces, improved tests and docs, optional provider adapters with strict privacy/consent.
3. **Defer responsibly:** platform integrations (MISP/OpenCTI/TheHive/Cortex), live intel APIs, malware sandboxes, ML training/claims, AI assistants, DB-backed case mgmt, and enterprise packaging until secure, testable, and justified. Local case JSON export (evidence hash + timeline) is available now; database-backed persistence is still deferred.

## 5. Source notes & follow-up validation
- **Locally reviewed:** PhishGuard repository and ThePhish source archive (`ThePhish-master.zip`, previously analyzed) for workflow/whitelist/observable concepts.
- **Pending deeper validation:** direct upstream source/license inspection and current-maintenance status checks for listed third-party projects/integrations (recommended before implementation or redistribution decisions).
- **Environment limitation:** automated web search results were limited during this pass; claims above reflect commonly documented public capabilities and should be verified against official project docs/repos before major design commitments.
