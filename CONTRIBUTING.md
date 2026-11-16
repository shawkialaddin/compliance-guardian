# Contributing

Thanks for helping improve compliance-guardian.

## Ground rules
- **No invented regulation.** Registry changes need an official source URL, edition and verification date. If you could only read a third-party summary, mark it `THIRD_PARTY_ONLY`; keep references `UNVERIFIED` unless the exact clause number and text were seen in the official document. Record the change in `compliance-guardian/registry/CHANGELOG.md`.
- **Detection rules need fixtures.** Each new rule requires a vulnerable example (in `tests/fixtures/vuln_*`) and, where practical, a secure counterpart that must stay free of MEDIUM+ findings.
- **Metadata:** add rules to `scripts/cg/catalog.py` with CWE, OWASP edition-tagged references, remediation and *verify-before-confirming* guidance.
- **Stdlib first.** The scanner must run with Python ≥3.10 + PyYAML only. No telemetry, no network calls, no source upload.
- **Never put real secrets, client code or personal data in fixtures or issues.**

## Development
```bash
git clone git@github.com:shawkialaddin/compliance-guardian.git && cd compliance-guardian
./install.sh --link          # symlink into ~/.claude/skills for live testing
python3 -m pytest compliance-guardian/tests -q
python3 compliance-guardian/scripts/cg.py scan . --fail-on HIGH   # dogfood (fixtures excluded)
```

## Pull requests
Describe the risk the rule addresses, the false-positive strategy, and the tests added. CI must pass.
