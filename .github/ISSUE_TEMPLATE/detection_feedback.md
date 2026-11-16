---
name: Detection feedback (false positive / false negative)
about: Report incorrect or missed phishing detection
title: "[Detection]: "
labels: detection
assignees: ''
---

## Type

- [ ] False positive (legitimate email flagged as risky)
- [ ] False negative (phishing/malicious email missed or under-scored)
- [ ] Scoring/explanation improvement

## Summary

<!-- Briefly describe the issue. -->

## Scan result (sanitized)

- Verdict/score:
- ML label/likelihood (if shown):
- Key findings triggered or missing:
- Whitelist used: (default/custom/none)

## Sanitized sample

<!-- Provide a redacted/sanitized raw source snippet or fixture that reproduces the issue.
DO NOT include real personal data, credentials, OTPs, tokens, private URLs, or confidential content.
Replace sensitive values with placeholders like <REDACTED_EMAIL>, <REDACTED_DOMAIN>, <REDACTED_URL>. -->

```text
Paste sanitized sample here
```

## Why this seems incorrect

<!-- Explain why the result should be different, with relevant context (e.g. known legitimate sender, expected indicators, auth context). -->

## Environment

- OS:
- Python version:
- PhishGuard version/commit:
- GUI or CLI:
- Command/options used:

## Additional context

<!-- Any other details that may help improve detection safely and explainably. -->
