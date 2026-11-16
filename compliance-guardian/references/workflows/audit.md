# Workflow: audit (full security + regulatory gap assessment)

1. Preconditions
   - `python3 "$CG" tools` — list available scanners; mention missing ones with optional install hints, do not install.
   - `python3 "$CG" validate-config` / `applicability`. If no config: say so, run baseline only, list applicability questions (profiles' `applicability_questions`), offer `init`.
   - `python3 "$CG" registry` — warn if sources are STALE (>180 days) and suggest `update-rules`.
2. Run: `python3 "$CG" report . --external` (add `--allow-network` only with user consent; it sends package names to vulnerability DBs, never source code).
3. Triage CRITICAL/HIGH candidates first, reading the actual code paths (callers, decorators, record rules, ACLs). Use parallel subagents only for large repos and give them the rule's verify guidance.
4. Manual review areas not covered by rules (record in report): business-logic authorization, multi-company isolation, portal flows, rate limiting, session management, backups, monitoring, breach runbook, data-subject-rights paths.
5. Regenerate reports after triage (`report` again) so statuses reflect verdicts.
6. Executive summary in chat: technical status, applicable frameworks (indications, not determinations), critical/high, unverified controls, manual + legal reviews required, next actions. Link `compliance/reports/`.
7. Never express compliance as a percentage or "compliant"; describe evidence.
