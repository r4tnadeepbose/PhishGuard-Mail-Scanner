# Licensing and Attribution Assessment

## 1. Scope and purpose

This document records licensing/attribution considerations for the reverse-engineering analysis of **ThePhish** (`C:\Users\boser\Downloads\ThePhish-master`) and ThePhish-inspired enhancements planned/implemented in **PhishGuard Mail Scanner** (`C:\Users\boser\Downloads\PhishGuard-Mail-Scanner`). It is an engineering assessment based on inspected repository files, not legal advice.

## 2. Source project (ThePhish) licensing facts (observed)

- **License file:** `C:\Users\boser\Downloads\ThePhish-master\LICENSE` contains the **GNU Affero General Public License v3.0 (AGPL-3.0)** text.
- **README notice:** `README.md` states: “ThePhish is an open-source and free software released under the [AGPL]…” (License section).
- **Copyright/attribution indicators:** repository metadata and docs identify the project as `emalderson/ThePhish`; individual source files inspected do not contain prominent per-file copyright headers, but the repository-level AGPL license and project attribution apply.
- **Third-party/runtime dependencies (declared):** `app/requirements.txt` includes packages such as Flask, Flask-SocketIO, eventlet, thehive4py, cortex4py, ioc-finder, requests, bs4/beautifulsoup4, python-magic, emoji, etc. Docker deployment references external service images (TheHive, Cortex, MISP, Elasticsearch, Cassandra, Redis, MySQL). Their licenses/terms are separate and must be reviewed before redistribution/bundling.

## 3. Target project (PhishGuard) licensing facts (observed)

- **License:** `C:\Users\boser\Downloads\PhishGuard-Mail-Scanner\LICENSE` is **MIT License** (Copyright (c) 2026 PhishGuard Contributors).
- **Project intent:** local, stdlib-first phishing triage scanner/GUI/CLI with optional, safe-by-default behavior.

## 4. AGPL-3.0 obligations and implications (relevant considerations)

> Summary for engineering planning only; consult qualified legal counsel for definitive interpretation.

- **Copyleft scope:** AGPL-3.0 requires that if you convey/distribute a work based on the Program (or modified versions), you must do so under AGPL-3.0 terms, provide Corresponding Source, preserve notices, and include license information.
- **Network use (Section 13):** for modified versions offered to users interacting remotely over a network, AGPL-3.0 requires providing access to the Corresponding Source of that modified version (subject to license terms). This is a key difference from GPL and is directly relevant to server-hosted SOC tools like ThePhish.
- **Derivative/combined work risk:** copying AGPL-covered code, or creating a derivative work closely based on AGPL code/expressive structure, can trigger AGPL obligations for the resulting covered work. Mere study of ideas/behavior and independent implementation in different code may reduce that risk, but boundaries can be fact-specific.
- **Attribution/notices:** license text and relevant copyright notices must be retained when required by the license for any reused/modified covered material.

## 5. Reuse, derivative-work, and integration assessment

| Item | Classification | Rationale / evidence | Action |
|---|---|---|---|
| ThePhish Python/JS/HTML/config logic in `app/*` | **AGPL-3.0 covered source (studied)** | Original implementation and repository licensed AGPL-3.0 | **Do not copy into PhishGuard MIT codebase.** Use for behavioral understanding only. |
| ThePhish architecture/workflow concepts (IMAP intake, IOC extraction/whitelist, analyzer orchestration, severity mapping, verdict/case/task flow, optional SOC integrations) | **Ideas/functional concepts (to be independently implemented)** | Concepts inferred from observed behavior/design; reimplementation planned in PhishGuard’s own structure/APIs | Implement original code, naming, and data models in PhishGuard; document inspiration and differences. |
| `analysis/*.md` in PhishGuard (this assessment set) | **Original documentation authored for PhishGuard** | Created from reverse-engineering observations; should not reproduce substantial AGPL source text beyond necessary short references | Keep factual, cite observed source paths/behavior, avoid copying large code blocks. |
| Direct vendoring/importing ThePhish as a component | **High AGPL/derivative impact** | Would incorporate/execute AGPL program code | Avoid unless an intentional AGPL-compatible licensing strategy is adopted for affected distribution/network use. |
| Optional adapters that interoperate via external APIs/protocols (TheHive/Cortex/MISP/IMAP) without including ThePhish code | **Likely independent integration layer (verify per implementation)** | Interoperability/interfaces and PhishGuard-side adapter code can be original | Keep adapters optional, clean-room implementation, no AGPL code/assets copied; review protocol/library licenses. |
| Third-party libraries used by PhishGuard | **Separate licenses** | PhishGuard currently stdlib-first; any future deps must be reviewed | Record dependency licenses and compatibility before adding. |

## 6. Required attribution and compliance actions

- **Preserve notices:** if any ThePhish source/config/text is ever copied or modified into this repository, retain AGPL license/copyright notices and comply fully with AGPL-3.0 terms (including source availability/network-use obligations as applicable).
- **Distinguish provenance:** keep “inspected/inspired by ThePhish (AGPL-3.0, emalderson/ThePhish)” notes in analysis/docs, and clearly label PhishGuard modules as independent implementations.
- **No silent relicensing:** do not relicense or present copied ThePhish material under MIT.
- **Document borrowing:** if architectural ideas or specific behavior mappings are adopted, record them in `analysis/LICENSING_AND_ATTRIBUTION.md` and relevant design docs with source references.
- **Dependency hygiene:** review licenses for any new libraries, tools, or bundled assets introduced during implementation.

## 7. Recommended path for PhishGuard

1. **Default (recommended): clean-room, independent implementation** of ThePhish-inspired capabilities in PhishGuard’s MIT codebase, with optional external-service adapters and no AGPL code reuse.
2. **Alternative (only if intentionally chosen): AGPL-compatible derivative strategy** — requires legal review, repository/license changes as needed, full AGPL compliance for distribution and network deployment, and clear contributor/process controls.
3. **Commercial/distribution caution:** obtain legal review before commercial distribution, SaaS/network offering, or embedding any ThePhish-derived material where licensing boundaries are unclear.

## 8. Attribution statement

- **Studied project:** *ThePhish* — automated phishing email analysis tool (TheHive/Cortex/MISP integration), repository `emalderson/ThePhish`, licensed under **AGPL-3.0** (see upstream `LICENSE` and `README.md`).
- **Use in this work:** static reverse-engineering analysis and extraction of functional understanding to inform independent, modular, and optionally-integrated enhancements in PhishGuard. No ThePhish source code has been intentionally copied into PhishGuard as part of this analysis documentation.

## 9. Open items requiring legal/maintainer review

- Confirm acceptable level of similarity for independently implemented orchestration/verdict/config-mapping behavior.
- Review licensing implications if future work adds direct integration plugins that ship alongside or embed third-party AGPL/GPL components.
- Perform dependency/license audit before publishing releases with new external libraries or adapters. 
