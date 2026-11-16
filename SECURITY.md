# Security Policy

## Supported versions

PhishGuard is provided as-is for educational/defensive triage use. Security fixes and improvements are applied to the latest version on the default branch when available.

| Version | Supported |
| --- | --- |
| Latest (default branch) | Yes |
| Older snapshots/releases | Best effort |

## Reporting a vulnerability

If you discover a security vulnerability, **please do not open a public GitHub issue**.

Instead, report it privately to the maintainers:

1. Use GitHub's **Private vulnerability reporting / Security Advisories** for this repository if enabled.
2. If private reporting is not available, open a minimal issue asking for a private contact channel **without disclosing vulnerability details**.

Please include (as applicable):
- A clear description of the issue and potential impact
- Steps to reproduce or a proof of concept (sanitized; no real sensitive email data)
- Affected files/components/versions
- Any suggested mitigation

## What to expect

- We will acknowledge receipt when possible and investigate the report.
- We may request additional information to reproduce or assess impact.
- We will work on a fix/mitigation and coordinate disclosure timing when appropriate.

## Scope and safety notes

PhishGuard analyzes user-provided email content locally. Reports may involve:
- Parsing/handling of untrusted email headers, MIME content, and URLs
- Detection logic that can have false positives/negatives
- Local file/report generation

Please avoid submitting reports that rely on executing attachments, browsing malicious URLs, or sharing unsanitized personal/confidential emails. When sharing samples, redact sensitive information.
