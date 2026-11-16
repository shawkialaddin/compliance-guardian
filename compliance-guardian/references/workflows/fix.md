# Workflow: fix (approved remediation)

For each finding (highest risk first), in this order:
1. Explain the risk and exploit/failure scenario in one paragraph.
2. Root cause (not just the symptom line).
3. Smallest safe fix that preserves business functionality; show the diff and any behaviour change. For Odoo: keep workflows, ACL semantics, multi-company, portal access, XML ids, upgrade path; prefer `_document_check_access`, record rules, field whitelists, parameterised SQL, `t-out`, `groups=`.
4. **Ask for authorization** unless the user already authorised fixes for this scope. Never alter business permissions or delete/rewrite production data silently; never touch production systems.
5. Add a regression test (see `templates/tests/`): it must fail on the vulnerable code and pass on the fix (e.g. portal user denied another partner's record; SQL payload treated as literal).
6. Run the relevant tests (`pytest`, or Odoo `--test-tags`) — if they cannot run here, say so explicitly; never claim they passed.
7. Re-scan the files (`scan --files ...`); record `triage <fp> --verdict fixed --rationale "<test name>, rescan clean"`.
8. Summarise: fixed / partially fixed / not fixed, with evidence.
