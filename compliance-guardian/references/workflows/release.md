# Workflow: release (readiness)

1. `python3 "$CG" release . --external` (exit 0 PASS/CONDITIONAL, 2 BLOCKED, 3 NEEDS_TRIAGE; `--strict` fails CONDITIONAL).
2. Triage all untriaged CRITICAL/HIGH; confirmed CRITICAL blocks (no waiver by default); confirmed HIGH blocks unless a valid exception exists in `.compliance-guardian.yaml approved_exceptions` (id, justification, approver, approval and expiry date). MEDIUM requires a documented risk decision (`triage --risk-decision`). LOW is recorded.
3. Re-run `release` after triage/fixes.
4. Present the four dimensions separately (technical gate / evidence completeness / legal approval / deployment authorization). Legal approvals and deployment authorization come only from `compliance/approvals.yaml` entries recorded by named humans — never write those records on the user's behalf without explicit instruction naming the approver.
5. List residual risk, unresolved findings, required manual/legal reviews.
6. Final sentence must make clear this is not legal certification.
