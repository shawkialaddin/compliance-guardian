# Severity, confidence and gates

Severity (impact if real): CRITICAL (remote unauthenticated compromise / mass data exposure) · HIGH (authenticated privilege escalation, IDOR on personal data, injection) · MEDIUM (needs conditions/user interaction, defence-in-depth gaps on sensitive data) · LOW (hardening) · INFO.
Confidence (likelihood the rule match is a real issue): high / medium / low. Test code lowers confidence.
Verification: candidate → confirmed | false_positive | fixed (recorded in compliance/triage.yaml with rationale + reviewer).

Default gate (configurable `release_gates`):
- CRITICAL confirmed → BLOCKED (not waivable by default)
- HIGH confirmed → BLOCKED unless valid approved exception (approver, approval date, unexpired expiry, justification)
- CRITICAL/HIGH candidate → NEEDS_TRIAGE (never PASS while untriaged)
- MEDIUM → CONDITIONAL until a documented risk decision exists
- LOW/INFO → recorded

Four separate outputs: technical security gate · regulatory evidence completeness · legal approval status · deployment authorization. A control is PASS only with evidence (automated_full rule set ran on a full scan with zero open findings, or a reviewer evidence record with refs + reviewer + date).
