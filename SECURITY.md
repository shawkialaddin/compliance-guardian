# Security policy

## Reporting a vulnerability
Please report vulnerabilities in compliance-guardian itself **privately** using GitHub's
"Report a vulnerability" (Security → Advisories) on this repository. Do not open public issues for
security problems, and do not include real secrets or personal data in reports.

We aim to acknowledge reports within 5 business days.

## Scope
- The scanner (`compliance-guardian/scripts`), installer (`install.sh`), hook integration, CI templates.
- Out of scope: findings produced *by* the scanner in your own code (those are your project's issues), and the
  intentionally vulnerable fixtures under `compliance-guardian/tests/fixtures/` (they are test data, not deployable code).

## Design commitments
- No telemetry; no source code upload; no automatic dependency installation.
- External tools that use the network run only with `--allow-network`.
- Secret values are redacted from all outputs.
- The PostToolUse hook never blocks or modifies edits; it only adds context.
