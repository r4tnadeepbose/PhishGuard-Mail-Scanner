# Contributing to PhishGuard Mail Scanner

Thanks for your interest in improving PhishGuard. Contributions that improve detection quality, safety, usability, performance, documentation, and tests are welcome.

## Ways to contribute

- Report bugs and false positives/negatives with reproducible examples (sanitize sensitive data first)
- Improve parsing, heuristic checks, explainability, and reporting
- Add tests and sample fixtures (safe/sanitized)
- Improve documentation (README, detection logic, usage guides)
- Enhance GUI/CLI ergonomics and performance

## Development setup

1. **Requirements:** Python 3.9+ (Tkinter required for GUI).
2. **Clone/fork the repo** and work from the project root.
3. **Run tests:**
   ```bash
   python -m unittest discover -s tests -p "test_*.py"
   ```
4. **Run locally:**
   ```bash
   python main.py          # GUI
   python cli.py --help    # CLI options
   ```

No third-party dependencies are required for the core scanner/ML/reporting modules.

## Guidelines

- **Safety first:** do not add features that execute attachments, auto-browse suspicious URLs, or upload user email content to third parties by default.
- **Explainability:** prefer transparent, documented checks and clear findings/reasoning over opaque behavior.
- **Accuracy claims:** avoid claiming perfect detection; document limitations and trade-offs.
- **Compatibility:** preserve existing CLI/GUI workflows where practical; note breaking changes clearly.
- **Privacy:** never include real sensitive/personal email content in issues, PRs, commits, or sample fixtures. Sanitize/redact all examples.
- **Performance:** keep scanning fast and local; precompile expensive patterns and avoid unnecessary work.

## Pull request process

1. Create a branch for your change.
2. Add/update tests for behavior changes when applicable.
3. Update documentation (`README.md`, `docs/`, `CHANGELOG.md`) as needed.
4. Run the test suite and ensure it passes.
5. Open a PR with:
   - a clear summary of the problem and solution
   - rationale/trade-offs (especially for detection/scoring changes)
   - notes on false positive/negative impact if relevant
   - screenshots for GUI changes (if applicable)

## Reporting security issues

Please do **not** open public issues for vulnerabilities that could put users at risk. See [SECURITY.md](SECURITY.md) for responsible disclosure guidance.

## Code of conduct

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
