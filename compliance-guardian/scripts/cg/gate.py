"""Release gates. Four independent dimensions, never collapsed into one 'compliant' verdict:

  1. technical_security_gate      PASS | CONDITIONAL | NEEDS_TRIAGE | BLOCKED
  2. regulatory_evidence          COMPLETE | INCOMPLETE  (+ counts per status)
  3. legal_approval               APPROVED | PENDING | NOT_REQUIRED_PER_CONFIG  (per framework)
  4. deployment_authorization     RECORDED (by whom) | NOT_RECORDED  -- the tool never grants it
"""
from __future__ import annotations

from .config import as_date
from .model import SEV_RANK

DEFAULT_POLICY = {
    "block_confirmed": ["CRITICAL", "HIGH"],
    "exception_allowed": ["HIGH", "MEDIUM", "LOW"],    # CRITICAL cannot be waived by default
    "block_untriaged": ["CRITICAL", "HIGH"],
    "require_risk_decision": ["MEDIUM"],
    "record_only": ["LOW", "INFO"],
}

EXIT = {"PASS": 0, "CONDITIONAL": 0, "NEEDS_TRIAGE": 3, "BLOCKED": 2}


def evaluate(findings, cfg, matrix, appl, approvals, triage) -> dict:
    pol = dict(DEFAULT_POLICY)
    pol.update(((cfg or {}).get("release_gates") or {}))
    tri = (triage or {}).get("findings") or {}
    blockers, triage_needed, risk_needed, recorded, waived = [], [], [], [], []
    for f in findings:
        if f.verification in ("false_positive", "fixed"):
            continue
        sev = f.severity
        if f.verification == "confirmed":
            if sev in pol["block_confirmed"]:
                if f.exception_id and sev in pol["exception_allowed"]:
                    waived.append(f)
                else:
                    blockers.append(f)
            elif sev in pol["require_risk_decision"]:
                decided = f.exception_id or (tri.get(f.fingerprint) or {}).get("risk_decision")
                (waived if decided else risk_needed).append(f)
            else:
                recorded.append(f)
        else:  # candidate
            if sev in pol["block_untriaged"]:
                triage_needed.append(f)
            elif sev in pol["require_risk_decision"]:
                risk_needed.append(f)
            else:
                recorded.append(f)
    if blockers:
        tech = "BLOCKED"
    elif triage_needed:
        tech = "NEEDS_TRIAGE"
    elif risk_needed:
        tech = "CONDITIONAL"
    else:
        tech = "PASS"

    active = [r for r in matrix if r["status"] != "NOT_APPLICABLE"]
    counts = {}
    for r in active:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    open_states = {"FAIL", "NOT_TESTED", "MANUAL_REVIEW_REQUIRED", "LEGAL_REVIEW_REQUIRED", "PARTIAL"}
    evidence = "COMPLETE" if active and not any(r["status"] in open_states for r in active) else "INCOMPLETE"

    legal = {}
    recs = {}
    for r in (approvals or {}).get("legal_reviews", []) or []:
        if isinstance(r, dict) and r.get("framework"):
            recs[r["framework"]] = r
    for fid, a in appl.items():
        if a["status"] in ("NOT_INDICATED", "DECLARED_NOT_APPLICABLE", "BASELINE") and not a.get("legal_review"):
            continue
        rec = recs.get(fid)
        if rec and str(rec.get("status")).lower() == "approved" and rec.get("reviewer") and as_date(rec.get("date")):
            legal[fid] = f"APPROVED by {rec['reviewer']} on {rec['date']}"
        elif rec and str(rec.get("status")).lower() == "rejected":
            legal[fid] = f"REJECTED by {rec.get('reviewer')}: {rec.get('notes', '')}"
        else:
            legal[fid] = "PENDING"

    dep = (approvals or {}).get("deployment_authorization") or {}
    if dep.get("approved_by") and as_date(dep.get("date")):
        deploy = f"RECORDED: approved by {dep['approved_by']} on {dep['date']} for release {dep.get('release', '?')}"
    else:
        deploy = "NOT_RECORDED (requires a named human authorizer; this tool never grants deployment authorization)"

    return dict(technical_gate=tech, exit_code=EXIT[tech], blockers=blockers, triage_needed=triage_needed,
                risk_decision_needed=risk_needed, waived=waived, recorded=recorded, evidence_status=evidence,
                evidence_counts=counts, legal=legal, deployment=deploy, policy=pol)


def rank(f):
    return SEV_RANK.get(f.severity, 9)
