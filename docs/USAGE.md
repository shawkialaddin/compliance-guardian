# Usage guide

## Lifecycle
| Phase | What to do |
|---|---|
| Before development | `/compliance-guardian design "<feature>"`: obligations (indications), personal data, authorization matrix, data flows, threats, PIA need, required tests |
| During implementation | Claude applies secure patterns; the hook flags risky edits immediately |
| After implementation | `/compliance-guardian review` → triage → `fix` (with authorization) → regression tests → re-scan |
| Before release | `/compliance-guardian release` → resolve blockers/triage → record approvals (humans) |

## Evidence files (in your project)
| File | Purpose | Written by |
|---|---|---|
| `.compliance-guardian.yaml` | facts, determinations, gates, exceptions | project team |
| `compliance/triage.yaml` | verdict per finding fingerprint (+ rationale, reviewer, risk decision) | reviewer / Claude via `cg.py triage` |
| `compliance/evidence.yaml` | evidence for manual/legal matrix rows (refs, reviewer, date) | reviewers |
| `compliance/approvals.yaml` | legal reviews per framework, deployment authorization | named humans only |
| `compliance/reports/*` | generated outputs | `cg.py report/release` |

Templates: `compliance-guardian/templates/evidence/`.

## Statuses
Finding verification: `candidate` → `confirmed` | `false_positive` | `fixed`.
Control status: `PASS` (evidence required) · `FAIL` · `PARTIAL` (automated part clean, manual part open) · `NOT_APPLICABLE` (framework not indicated / declared N/A) · `NOT_TESTED` · `MANUAL_REVIEW_REQUIRED` · `LEGAL_REVIEW_REQUIRED`.

## Release gate exit codes
`0` PASS or CONDITIONAL (use `--strict` to fail CONDITIONAL) · `2` BLOCKED · `3` NEEDS_TRIAGE.

## Exceptions
```yaml
approved_exceptions:
  - id: EXC-2026-001
    fingerprint: 0123456789abcdef        # from findings.json / scan output
    justification: "Endpoint intentionally public; returns published products only"
    compensating_controls: "domain + field whitelist; rate limit at proxy"
    approved_by: "Security lead"
    approved_on: "2026-11-01"
    expires_on: "2027-05-01"
```
Expired or incomplete exceptions are ignored and reported.
