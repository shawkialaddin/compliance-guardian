# Security-by-design lifecycle

## Before development (design)
Produce a short design note (in chat or `compliance/design/<feature>.md`):
- Applicable obligations: from `applicability` (indications) — list legal questions as LEGAL_REVIEW_REQUIRED.
- Personal/sensitive data: which fields, purpose, legal basis owner, retention, who can see them.
- Authorization: actors (public, portal, internal user, manager, admin, cron, integration), operations, deny-by-default rules, multi-company.
- Data flows and trust boundaries (inputs, outbound calls, storage, exports, countries).
- Foreseeable threats (STRIDE-lite) and abuse cases (IDOR, mass assignment, injection, SSRF, upload abuse, brute force).
- PIA/DPIA needed? (sensitive data, large scale, monitoring, new tech → LEGAL_REVIEW_REQUIRED decision).
- Required tests: authorization boundary tests, injection tests, regression tests.

## During implementation
Recommend secure patterns; refuse demonstrably unsafe ones (string-built SQL, eval of input, sudo on request ids, csrf=False without signatures, secrets in code, disabled TLS). Minimise data; `groups=` on sensitive fields; least privilege; secure defaults; no sensitive data in logs/errors; secrets from env/secret manager. The PostToolUse hook gives incremental feedback — verify and address it.

## After implementation
`scan --mode changed`; run available tests; validate authorization boundaries with tests; report; fix (authorized); re-check.

## Before release
`release` workflow: residual risk, unresolved findings, exceptions with approvals, evidence. Never claim certification.
