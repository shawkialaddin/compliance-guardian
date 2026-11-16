# Workflow: review (current changes or a file)

1. Scope
   - With a path: `python3 "$CG" scan <path> --files <path>` (or the directory).
   - Without: `python3 "$CG" scan . --mode changed` (uncommitted + staged + untracked). If not a git repo, ask which files.
   - Also read the diff (`git diff`, `git diff --cached`) yourself: the scanner cannot see design flaws.
2. Context checks the scanner cannot do — review the changed code for:
   - authorization on every new entry point (controller, RPC-callable method, cron, server action);
   - new personal-data fields (purpose, groups=, retention, logging, export);
   - trust boundaries crossed (request → ORM/SQL/shell/filesystem/HTTP/templating).
3. Verify each candidate (`python3 "$CG" explain <rule>` → "Verify before confirming"). Classify: confirmed / false_positive (with rationale) / needs-human. Record with `triage`.
4. Report using `references/finding-format.md`, ordered by risk. No generic checklists — only concrete issues in this code.
5. Offer fixes (`fix` workflow). Do not edit without authorization unless the user asked for fixes.
