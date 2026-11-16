"""Markdown/JSON/SARIF report generation (compliance/reports/)."""
from __future__ import annotations

import json
from pathlib import Path

from . import catalog
from .sarif import to_sarif

DISCLAIMER = ("> **Not a legal compliance determination.** This report records automated and reviewer-verified "
              "*technical* evidence. Legal applicability and compliance conclusions require review by qualified "
              "legal/privacy counsel. Passing automated checks does not certify compliance with any law or standard.")


def _fx(f):
    return f"`{f.id}` **{f.severity}**/{f.confidence} `{f.rule_id}` {f.path}:{f.line} — {f.message}"


def _md_escape(s):
    return str(s or "").replace("|", "\\|").replace("\n", " ")


def write_all(out_dir: Path, scan_res, matrix, appl, gate_res, sources, ext_status=None):
    out_dir.mkdir(parents=True, exist_ok=True)
    meta, findings, inv, cfg = scan_res["meta"], scan_res["findings"], scan_res["inventory"], scan_res["config"]
    files = {}
    files["findings.json"] = json.dumps(dict(meta=meta, external_tools=ext_status or {},
                                             findings=[f.to_dict() for f in findings]), indent=2, default=str)
    files["findings.sarif"] = json.dumps(to_sarif(findings, meta), indent=2)
    files["security-report.md"] = security_report(meta, findings, appl, gate_res, ext_status)
    files["regulatory-matrix.md"] = regulatory_matrix(matrix, appl, sources)
    files["privacy-assessment.md"] = privacy_assessment(inv, findings, cfg, appl)
    files["remediation-plan.md"] = remediation_plan(findings)
    files["release-readiness.md"] = release_readiness(meta, gate_res, appl)
    files["regulatory-matrix.json"] = json.dumps(matrix, indent=2, default=str)
    for name, content in files.items():
        (out_dir / name).write_text(content, encoding="utf-8")
    return sorted(files)


def _counts(findings):
    c = {}
    for f in findings:
        if f.verification in ("false_positive", "fixed"):
            continue
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def security_report(meta, findings, appl, g, ext_status):
    c = _counts(findings)
    open_f = [f for f in findings if f.verification not in ("false_positive", "fixed")]
    crit_high = [f for f in open_f if f.severity in ("CRITICAL", "HIGH")]
    unverified = [f for f in open_f if f.verification == "candidate"]
    L = ["# Security Report", "", DISCLAIMER, "",
         f"Scan `{meta['scan_id']}` · mode **{meta['mode']}** · {meta['files_scanned']} files · "
         f"compliance-guardian {meta['version']} · {meta['started']} · Odoo version: {meta.get('odoo_version') or 'n/a'}",
         "", "## Executive summary", "",
         f"- **Technical security gate:** `{g['technical_gate']}`",
         f"- **Open findings:** " + (", ".join(f"{k}: {v}" for k, v in sorted(c.items(), key=lambda x:
                                     ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x[0]))) or "none"),
         f"- **Confirmed vs. candidate:** {len(open_f) - len(unverified)} confirmed, {len(unverified)} candidate "
         "(candidates are rule matches pending contextual verification)",
         "- **Frameworks considered:** " + "; ".join(f"{k} = {v['status']}" for k, v in appl.items()),
         f"- **Regulatory evidence:** {g['evidence_status']} ({', '.join(f'{k}: {v}' for k, v in g['evidence_counts'].items())})",
         f"- **Legal reviews pending:** {sum(1 for v in g['legal'].values() if v == 'PENDING')}",
         "", "### Critical and high findings", ""]
    L += [f"- {_fx(f)} _(verification: {f.verification})_" for f in crit_high] or ["- None open."]
    L += ["", "### Recommended next actions", ""]
    actions = []
    if g["triage_needed"]:
        actions.append(f"Triage {len(g['triage_needed'])} CRITICAL/HIGH candidate(s): verify exploitability in "
                       "context and record verdicts in `compliance/triage.yaml`.")
    if g["blockers"]:
        actions.append(f"Remediate {len(g['blockers'])} confirmed blocking finding(s) (see remediation-plan.md).")
    if g["risk_decision_needed"]:
        actions.append(f"Record risk decisions for {len(g['risk_decision_needed'])} MEDIUM finding(s).")
    if not meta.get("config_present"):
        actions.append("Create `.compliance-guardian.yaml` so regulatory applicability can be assessed.")
    if any(v == "PENDING" for v in g["legal"].values()):
        actions.append("Obtain legal review for frameworks marked PENDING (regulatory-matrix.md).")
    L += [f"{i}. {a}" for i, a in enumerate(actions, 1)] or ["1. Maintain: re-run on changes."]
    L += ["", "## External tools", ""]
    L += [f"- `{k}`: {v}" for k, v in (ext_status or {}).items()] or ["- External scanners not run (use --external)."]
    L += ["", "## All findings", ""]
    for f in findings:
        r = catalog.R.get(f.rule_id, {})
        L += [f"### {f.id} — {f.title}", "",
              "| Field | Value |", "|---|---|",
              f"| Severity / confidence | {f.severity} / {f.confidence} |",
              f"| Verification | {f.verification}{(' — ' + _md_escape(f.triage_note)) if f.triage_note else ''} |",
              f"| Rule | `{f.rule_id}` ({f.tool}) |",
              f"| Location | `{f.path}:{f.line}` |",
              f"| CWE / OWASP | {', '.join(f.cwe) or '—'} / {', '.join(f.owasp) or '—'} |",
              f"| Fingerprint | `{f.fingerprint}` |",
              f"| Exception | {f.exception_id or '—'} |", "",
              f"**Finding:** {f.message}", ""]
        if f.snippet:
            L += ["```", f.snippet, "```", ""]
        if r.get("verify"):
            L += [f"**Verify before confirming:** {r['verify']}", ""]
        if f.remediation:
            L += [f"**Remediation:** {f.remediation}", ""]
        if f.example_fix:
            L += ["```python", f.example_fix, "```", ""]
    return "\n".join(L) + "\n"


def regulatory_matrix(matrix, appl, sources):
    srcs = {s["framework"]: s for s in (sources or {}).get("sources", []) if s.get("framework")}
    L = ["# Regulatory Control Matrix", "", DISCLAIMER, "",
         "Regulation → reference → engineering requirement → source → test → evidence → status. "
         "`reference_status: UNVERIFIED` means the clause number was not confirmed against the official text and "
         "must not be cited externally until verified.", "", "## Applicability (engineering indication only)", "",
         "| Framework | Indication | Legal review | Reasons | Source document (verified on) |", "|---|---|---|---|---|"]
    for fid, a in appl.items():
        s = srcs.get(fid, {})
        L.append(f"| {fid} | {a['status']} | {'REQUIRED' if a.get('legal_review') else '—'} | "
                 f"{_md_escape('; '.join(a['reasons']))} | {_md_escape(s.get('document', ''))} "
                 f"{_md_escape(s.get('edition', ''))} ({s.get('verified_on', '?')}, {s.get('verification', '?')}) |")
    L += ["", "## Controls", "",
          "| Framework | Control | Reference (status) | Requirement | Verification | Rules/Tests | Source files | Evidence | Status |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in matrix:
        if r["status"] == "NOT_APPLICABLE":
            continue
        L.append(f"| {r['framework']} | {r['control']} | {_md_escape(r['reference'])} ({r['reference_status']}) | "
                 f"{_md_escape(r['requirement'])} | {r['verification']} | "
                 f"{_md_escape(', '.join(r['rules'] + r['tests'])) or '—'} | {_md_escape(', '.join(r['source_files'][:3])) or '—'} | "
                 f"{_md_escape('; '.join(r['evidence'])) or '—'} | **{r['status']}**"
                 f"{(' — ' + _md_escape(r['note'])) if r['note'] else ''} |")
    na = [r for r in matrix if r["status"] == "NOT_APPLICABLE"]
    if na:
        L += ["", f"_{len(na)} requirement(s) from frameworks not indicated by configuration are omitted "
                  "(NOT_APPLICABLE per config; not a legal conclusion)._"]
    return "\n".join(L) + "\n"


def privacy_assessment(inv, findings, cfg, appl):
    cfg = cfg or {}
    L = ["# Privacy Assessment", "", DISCLAIMER, "", "## Declared processing context", ""]
    for k in ("processing_role", "processing_countries", "data_subject_locations", "personal_data_categories",
              "sensitive_data_categories", "hosting", "backup_countries", "subprocessors", "transfer_destinations"):
        L.append(f"- **{k}:** {_md_escape(json.dumps(cfg.get(k), default=str)) if cfg.get(k) is not None else '_not declared_'}")
    L += ["", "## Personal-data inventory (detected in code)", "",
          "Classification is a name-based engineering hint; legal categorisation (e.g. GDPR Art. 9, PDPL sensitive "
          "data) must be confirmed.", "",
          "| Model | Field | Type | Category hint | Sensitive hint | groups= | Tracked | Location |",
          "|---|---|---|---|---|---|---|---|"]
    for e in inv:
        L.append(f"| {e['model']} | {e['field']} | {e['type']} | {e['category']} | {'yes' if e['sensitive_hint'] else 'no'} | "
                 f"{e['groups'] or '—'} | {'yes' if e['tracked'] else 'no'} | `{e['path']}:{e['line']}` |")
    if not inv:
        L.append("| — | — | — | — | — | — | — | — |")
    priv = [f for f in findings if f.category in ("privacy", "compliance")]
    L += ["", "## Privacy findings", ""] + ([f"- {_fx(f)}" for f in priv] or ["- None."])
    has_sensitive = any(e["sensitive_hint"] for e in inv) or cfg.get("sensitive_data_categories")
    L += ["", "## Privacy engineering checklist (manual unless evidence is recorded)", "",
          "| Area | Question | Status |", "|---|---|---|"]
    checks = [
        ("Lawful basis", "Is a lawful basis / legal condition documented per processing purpose?", "LEGAL_REVIEW_REQUIRED"),
        ("Transparency", "Is a privacy notice presented at collection points (website/portal forms, apps)?", "MANUAL_REVIEW_REQUIRED"),
        ("Minimisation", "Is every personal field above necessary for a declared purpose?", "MANUAL_REVIEW_REQUIRED"),
        ("Consent", "Where consent is the basis, is it recorded, granular and withdrawable? (only where consent is actually required)", "LEGAL_REVIEW_REQUIRED"),
        ("Access / portability", "Can the data subject's data be exported (access, copy, portability where applicable)?", "MANUAL_REVIEW_REQUIRED"),
        ("Rectification", "Can data be corrected through an authorised path?", "MANUAL_REVIEW_REQUIRED"),
        ("Erasure / anonymisation", "Is there a deletion/anonymisation path that respects legal retention (accounting/tax records)?",
         "MANUAL_REVIEW_REQUIRED"),
        ("Retention", "Are retention periods defined and enforced per category?", "MANUAL_REVIEW_REQUIRED"),
        ("Logs", "Are logs free of credentials and unnecessary personal data?", "MANUAL_REVIEW_REQUIRED"),
        ("Transfers", "Are cross-border transfers/backups/subprocessors documented with a legal mechanism?", "LEGAL_REVIEW_REQUIRED"),
        ("Breach", "Can breaches be detected and escalated within regulatory timelines (e.g. GDPR Art. 33, PDPL IR Art. 24)?",
         "MANUAL_REVIEW_REQUIRED"),
        ("Impact assessment", "Is a DPIA/PIA required (sensitive data, large scale, monitoring)?",
         "LEGAL_REVIEW_REQUIRED" if has_sensitive else "MANUAL_REVIEW_REQUIRED"),
    ]
    L += [f"| {a} | {q} | {s} |" for a, q, s in checks]
    return "\n".join(L) + "\n"


def remediation_plan(findings):
    L = ["# Remediation Plan", "", DISCLAIMER, "",
         "Ordered by risk. Apply fixes only when authorized; every fix requires a regression test and a re-scan.", ""]
    open_f = [f for f in findings if f.verification not in ("false_positive", "fixed") and f.severity != "INFO"]
    if not open_f:
        return "\n".join(L + ["No open findings."]) + "\n"
    L += ["| # | Finding | Severity | Verification | Location | Smallest safe fix | Regression test | Status |",
          "|---|---|---|---|---|---|---|---|"]
    for i, f in enumerate(open_f, 1):
        L.append(f"| {i} | `{f.id}` {_md_escape(f.title)} | {f.severity} | {f.verification} | `{f.path}:{f.line}` | "
                 f"{_md_escape(f.remediation[:220])} | _to add_ | {'EXCEPTION ' + f.exception_id if f.exception_id else 'OPEN'} |")
    return "\n".join(L) + "\n"


def release_readiness(meta, g, appl):
    L = ["# Release Readiness", "", DISCLAIMER, "",
         f"Scan `{meta['scan_id']}` ({meta['mode']}) at {meta['started']}", "",
         "| Dimension | Status |", "|---|---|",
         f"| 1. Technical security gate | **{g['technical_gate']}** |",
         f"| 2. Regulatory evidence completeness | **{g['evidence_status']}** "
         f"({', '.join(f'{k}: {v}' for k, v in g['evidence_counts'].items()) or 'no active controls'}) |",
         f"| 3. Legal approval | " + ("; ".join(f"{k}: {v}" for k, v in g["legal"].items()) or "no framework requires review per config")
         + " |",
         f"| 4. Final deployment authorization | {g['deployment']} |", "",
         "## Gate policy", "", "```json", json.dumps(g["policy"], indent=2), "```", ""]
    for title, items in (("Blocking (confirmed, no valid exception)", g["blockers"]),
                         ("Untriaged CRITICAL/HIGH candidates", g["triage_needed"]),
                         ("MEDIUM requiring a documented risk decision", g["risk_decision_needed"]),
                         ("Accepted via approved exception / risk decision", g["waived"])):
        L += [f"## {title}", ""] + ([f"- {_fx(f)}" + (f" (exception {f.exception_id})" if f.exception_id else "")
                                     for f in items] or ["- None."]) + [""]
    L += ["## Residual risk", "", "_Reviewer to summarise residual risk accepted for this release, with owner._", ""]
    return "\n".join(L) + "\n"
