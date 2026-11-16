"""compliance-guardian self-test suite: detection, false-positive control, redaction, reporting,
gates, matrix evidence rules, applicability, registry integrity, hook, incremental scanning, skill spec."""
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from cg import catalog, gate, registry
from cg.config import validate
from cg.sarif import to_sarif
from cg.scanner import apply_triage_and_exceptions, scan

SKILL = Path(__file__).resolve().parents[1]
FIX = SKILL / "tests" / "fixtures"
CG = [sys.executable, str(SKILL / "scripts" / "cg.py")]
SECRETS_IN_FIXTURES = ["SuperSecret123", "pk_9f8a7Bc6D5e4F3g2H1", "dj4ng0-1nsecure-K3y-9f8a7b6c5d"]


def rules_found(res, min_conf=None):
    return {f.rule_id for f in res["findings"]}


@pytest.fixture(scope="module")
def vuln():
    return scan(FIX / "vuln_odoo")


@pytest.fixture(scope="module")
def safe():
    return scan(FIX / "safe_odoo")


# ------------------------------------------------------------------ detection
EXPECTED_ODOO = {
    "CG-ODOO-SUDO-001", "CG-ODOO-SUDO-002", "CG-ODOO-SUDO-003", "CG-ODOO-SUDO-004", "CG-ODOO-AUTH-001",
    "CG-ODOO-AUTH-002", "CG-ODOO-CSRF-001", "CG-ODOO-CORS-001", "CG-ODOO-UPLOAD-001", "CG-ODOO-RULE-001",
    "CG-ODOO-RULE-002", "CG-ODOO-GROUP-001", "CG-ODOO-ACL-001", "CG-ODOO-ACL-003", "CG-ODOO-CONF-001",
    "CG-ODOO-CONF-002", "CG-ODOO-CONF-003", "CG-ODOO-XSS-001", "CG-ODOO-XSS-002", "CG-ODOO-XSS-003",
    "CG-ODOO-VIEW-001", "CG-ODOO-RATE-001", "CG-ODOO-INFO-001", "CG-ODOO-PRIV-002", "CG-ODOO-HOOK-001",
    "CG-PY-SQLI-001", "CG-PY-CMDI-001", "CG-PY-EVAL-001", "CG-PY-DESER-001", "CG-PY-SSRF-001", "CG-PY-TLS-001",
    "CG-PY-TIMEOUT-001", "CG-PY-LOG-001", "CG-PY-SECRET-001", "CG-PY-CRYPTO-001", "CG-PY-CRYPTO-002",
    "CG-PY-PATH-001", "CG-PRIV-001", "CG-JS-XSS-001", "CG-JS-XSS-002", "CG-JS-EVAL-001", "CG-JS-STORAGE-001",
    "CG-SEC-002", "CG-IAC-DOCKER-001", "CG-IAC-DOCKER-002", "CG-IAC-DOCKER-003", "CG-IAC-DOCKER-004",
    "CG-IAC-COMPOSE-001", "CG-IAC-COMPOSE-002",
}


def test_vulnerable_odoo_all_expected_rules_detected(vuln):
    missing = EXPECTED_ODOO - rules_found(vuln)
    assert not missing, f"missed detections: {sorted(missing)}"


def test_sql_injection_from_public_route_is_critical_high_confidence(vuln):
    f = [f for f in vuln["findings"] if f.rule_id == "CG-PY-SQLI-001" and "controllers" in f.path]
    assert f and f[0].severity == "CRITICAL" and f[0].confidence == "high"


def test_identifier_only_sql_is_low(vuln):
    f = [f for f in vuln["findings"] if f.rule_id == "CG-PY-SQLI-001" and "_table" in f.snippet]
    assert f and all(x.severity == "LOW" for x in f)


def test_vulnerable_python_detected():
    found = rules_found(scan(FIX / "vuln_python"))
    assert {"CG-PY-CORS-001", "CG-PY-JWT-001", "CG-PY-SECRET-001", "CG-PY-DESER-001", "CG-PY-DJANGO-001",
            "CG-PY-TIMING-001"} <= found


def test_safe_counterpart_has_no_medium_or_higher(safe):
    bad = [(f.rule_id, f.path, f.line) for f in safe["findings"] if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
    assert not bad, f"false positives on secure code: {bad}"


def test_every_finding_has_known_rule_and_fields(vuln):
    for f in vuln["findings"]:
        assert f.rule_id in catalog.R
        assert f.id.startswith("CG-F-") and len(f.fingerprint) == 16
        assert f.verification == "candidate"
        assert f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


# ------------------------------------------------------------------ redaction / no secret leakage
def test_secrets_redacted_everywhere(vuln, tmp_path):
    blob = json.dumps([f.to_dict() for f in vuln["findings"]])
    blob += json.dumps(to_sarif(vuln["findings"], vuln["meta"]))
    for s in SECRETS_IN_FIXTURES[:2]:
        assert s not in blob, f"secret value leaked: {s[:4]}..."


def test_report_outputs_contain_no_secrets(tmp_path):
    proj = tmp_path / "proj"
    shutil.copytree(FIX / "vuln_odoo", proj)
    shutil.copy(FIX / "vuln_python" / "app.py", proj / "app.py")
    subprocess.run(["git", "init", "-q", str(proj)], check=True)
    r = subprocess.run(CG + ["report", str(proj)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = proj / "compliance" / "reports"
    names = {p.name for p in out.iterdir()}
    assert {"security-report.md", "regulatory-matrix.md", "privacy-assessment.md", "remediation-plan.md",
            "release-readiness.md", "findings.sarif"} <= names
    text = "".join(p.read_text() for p in out.iterdir())
    for s in SECRETS_IN_FIXTURES:
        assert s not in text
    assert "Not a legal compliance determination" in (out / "security-report.md").read_text()


# ------------------------------------------------------------------ SARIF
def test_sarif_structure(vuln):
    s = to_sarif(vuln["findings"], vuln["meta"])
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert len(run["results"]) == len(vuln["findings"])
    ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in ids for r in run["results"])
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in run["results"])


# ------------------------------------------------------------------ gates
def _one(rule="CG-ODOO-SUDO-001", severity="HIGH"):
    res = scan(FIX / "vuln_odoo")
    f = next(x for x in res["findings"] if x.rule_id == rule)
    f.severity = severity
    return f


def test_gate_untriaged_high_never_passes():
    f = _one()
    g = gate.evaluate([f], {}, [], {}, {}, {})
    assert g["technical_gate"] == "NEEDS_TRIAGE" and g["exit_code"] != 0


def test_gate_confirmed_high_blocks_and_valid_exception_waives():
    f = _one()
    f.verification = "confirmed"
    assert gate.evaluate([f], {}, [], {}, {}, {})["technical_gate"] == "BLOCKED"
    future = (dt.date.today() + dt.timedelta(days=30)).isoformat()
    cfg = {"approved_exceptions": [{"id": "EXC-1", "fingerprint": f.fingerprint, "justification": "documented reason",
                                    "approved_by": "Sec Lead", "approved_on": "2026-01-01", "expires_on": future}]}
    apply_triage_and_exceptions([f], cfg, {})
    assert f.exception_id == "EXC-1"
    assert gate.evaluate([f], cfg, [], {}, {}, {})["technical_gate"] == "PASS"


def test_expired_or_unapproved_exception_rejected():
    f = _one()
    f.verification = "confirmed"
    cfg = {"approved_exceptions": [{"id": "EXC-2", "fingerprint": f.fingerprint, "justification": "documented reason",
                                    "approved_by": "Sec Lead", "approved_on": "2025-01-01", "expires_on": "2025-06-01"},
                                   {"id": "EXC-3", "fingerprint": f.fingerprint, "justification": "no approver here"}]}
    apply_triage_and_exceptions([f], cfg, {})
    assert f.exception_id is None
    assert gate.evaluate([f], cfg, [], {}, {}, {})["technical_gate"] == "BLOCKED"


def test_critical_cannot_be_waived_by_default():
    f = _one(severity="CRITICAL")
    f.verification = "confirmed"
    f.exception_id = "EXC-X"
    assert gate.evaluate([f], {}, [], {}, {}, {})["technical_gate"] == "BLOCKED"


def test_triage_false_positive_requires_rationale():
    f = _one()
    apply_triage_and_exceptions([f], {}, {"findings": {f.fingerprint: {"verdict": "false_positive"}}})
    assert f.verification == "candidate"
    apply_triage_and_exceptions([f], {}, {"findings": {f.fingerprint: {"verdict": "false_positive",
                                                                       "rationale": "route is admin-only"}}})
    assert f.verification == "false_positive"
    assert gate.evaluate([f], {}, [], {}, {}, {})["technical_gate"] == "PASS"


def test_medium_needs_risk_decision():
    f = _one(rule="CG-ODOO-CSRF-001", severity="MEDIUM")
    f.verification = "confirmed"
    assert gate.evaluate([f], {}, [], {}, {}, {})["technical_gate"] == "CONDITIONAL"
    tri = {"findings": {f.fingerprint: {"risk_decision": "fix in sprint 12"}}}
    assert gate.evaluate([f], {}, [], {}, {}, tri)["technical_gate"] == "PASS"


def test_deployment_authorization_never_granted_by_tool():
    g = gate.evaluate([], {}, [], {}, {}, {})
    assert g["deployment"].startswith("NOT_RECORDED")


# ------------------------------------------------------------------ matrix & applicability
def _matrix(res, cfg):
    _, fws = registry.load_registry()
    appl = registry.applicability(cfg, fws)
    return appl, registry.compute_matrix(fws, appl, res["findings"], set(res["meta"]["rules_run"]), {}, res["meta"])


def test_no_pass_without_evidence(vuln):
    _, rows = _matrix(vuln, None)
    for r in rows:
        if r["status"] == "PASS":
            assert r["evidence"], r
        if r["verification"] in ("manual", "legal"):
            assert r["status"] in ("MANUAL_REVIEW_REQUIRED", "LEGAL_REVIEW_REQUIRED", "NOT_APPLICABLE")


def test_pass_only_for_fully_automated_controls_on_clean_full_scan(safe):
    _, rows = _matrix(safe, None)
    passed = [r for r in rows if r["status"] == "PASS"]
    assert passed and all(r["verification"] == "automated_full" for r in passed)


def test_no_config_means_undetermined_not_assumed():
    _, fws = registry.load_registry()
    appl = registry.applicability(None, fws)
    assert all(a["status"] in ("UNDETERMINED", "BASELINE") for a in appl.values())


def test_location_alone_does_not_trigger_nca_ecc():
    _, fws = registry.load_registry()
    cfg = {"processing_countries": ["SA"], "organization": {"classification": ["private"]},
           "personal_data_categories": ["contact"]}
    appl = registry.applicability(cfg, fws)
    assert appl["ksa_nca_ecc"]["status"] == "NOT_INDICATED"
    assert appl["ksa_pdpl"]["status"] == "INDICATED" and appl["ksa_pdpl"]["legal_review"]
    gov = dict(cfg, organization={"classification": ["government"]})
    assert registry.applicability(gov, fws)["ksa_nca_ecc"]["status"] == "INDICATED"


def test_declared_applicability_requires_named_determination():
    _, fws = registry.load_registry()
    cfg = {"regulatory_requirements": [{"framework": "eu_gdpr", "status": "applicable"}]}
    a = registry.applicability(cfg, fws)["eu_gdpr"]
    assert a["status"] == "DECLARED_APPLICABLE" and a["legal_review"] is True


def test_cross_border_transfer_flagged_for_legal_review():
    from cg.scanner import transfer_findings
    out = transfer_findings({"data_subject_locations": ["SA"], "hosting": {"country": "DE"}})
    assert out and out[0].rule_id == "CG-PRIV-005" and "LEGAL_REVIEW_REQUIRED" in out[0].message


# ------------------------------------------------------------------ registry integrity
def test_registry_integrity():
    sources, fws = registry.load_registry()
    src_ids = {s["id"] for s in sources["sources"]}
    for s in sources["sources"]:
        assert s["verification"] in ("CONFIRMED", "PARTIAL", "THIRD_PARTY_ONLY", "UNVERIFIED")
        assert s.get("verified_on")
        if s["verification"] == "CONFIRMED":
            assert str(s.get("url", "")).startswith("https://")
    seen = set()
    for fid, fw in fws.items():
        assert fw["source"] in src_ids
        assert fw["obligation_type"] in ("legal", "contractual", "best_practice", "recommended")
        for c in fw["controls"]:
            assert c["reference_status"] in ("VERIFIED", "UNVERIFIED"), c["id"]
            for er in c["engineering_requirements"]:
                assert er["id"] not in seen, f"duplicate requirement id {er['id']}"
                seen.add(er["id"])
                assert er["verification"] in ("automated_full", "automated_partial", "manual", "legal")
                for r in er.get("rules", []):
                    assert r in catalog.R or r.startswith("EXT-"), f"unknown rule {r} in {er['id']}"


def test_unverified_sources_have_no_verified_controls():
    sources, fws = registry.load_registry()
    by_id = {s["id"]: s for s in sources["sources"]}
    for fid, fw in fws.items():
        if by_id[fw["source"]]["verification"] in ("THIRD_PARTY_ONLY", "UNVERIFIED", "PARTIAL"):
            assert all(c["reference_status"] == "UNVERIFIED" for c in fw["controls"]), fid


# ------------------------------------------------------------------ config/schema/semgrep/skill spec
def test_example_config_and_profiles_validate():
    cfg = yaml.safe_load((SKILL / "templates" / "compliance-guardian.example.yaml").read_text())
    assert validate(cfg) == []
    for p in (SKILL / "profiles").glob("*.yaml"):
        prof = yaml.safe_load(p.read_text())
        _, fws = registry.load_registry()
        assert set(prof["frameworks"]) <= set(fws), p.name
        assert validate({"schema_version": 1, "profiles": [p.stem]}) == []


def test_invalid_config_rejected():
    errs = validate({"schema_version": 1, "processing_countries": ["Saudi"], "bogus": 1})
    assert len(errs) >= 2


def test_semgrep_rules_well_formed():
    ids = set()
    for p in (SKILL / "rules" / "semgrep").glob("*.yaml"):
        for r in yaml.safe_load(p.read_text())["rules"]:
            assert r["id"] not in ids
            ids.add(r["id"])
            assert r["severity"] in ("ERROR", "WARNING", "INFO")
            assert r["languages"] and r["message"]
            assert any(k in r for k in ("pattern", "patterns", "pattern-either", "pattern-regex"))
            assert r["metadata"]["cg_rule"] in catalog.R
    assert len(ids) >= 20


def test_skill_md_frontmatter():
    text = (SKILL / "SKILL.md").read_text()
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert m
    fm = yaml.safe_load(m.group(1))
    assert fm["name"] == "compliance-guardian" == SKILL.name
    assert re.fullmatch(r"[a-z0-9-]{1,64}", fm["name"])
    assert 50 < len(fm["description"]) <= 1024
    assert "argument-hint" in fm
    for wf in ("audit", "review", "odoo", "privacy", "fix", "release", "update-rules"):
        assert (SKILL / "references" / "workflows" / f"{wf}.md").exists()
    assert len(text.splitlines()) < 500


# ------------------------------------------------------------------ hook & incremental
def _hook(payload, env=None):
    return subprocess.run(CG + ["hook"], input=json.dumps(payload), capture_output=True, text=True,
                          env={**os.environ, **(env or {})}, timeout=30)


def test_hook_reports_candidates_for_vulnerable_edit():
    p = FIX / "vuln_odoo" / "vuln_portal" / "controllers" / "main.py"
    r = _hook({"tool_name": "Edit", "tool_input": {"file_path": str(p)}})
    assert r.returncode == 0
    ctx = json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "CG-PY-SQLI-001" in ctx and "candidate" in ctx
    assert "SuperSecret123" not in ctx


def test_hook_silent_for_safe_file_and_when_disabled():
    safe = FIX / "safe_odoo" / "safe_portal" / "controllers" / "main.py"
    assert _hook({"tool_input": {"file_path": str(safe)}}).stdout.strip() == ""
    vuln = FIX / "vuln_odoo" / "vuln_portal" / "controllers" / "main.py"
    assert _hook({"tool_input": {"file_path": str(vuln)}}, {"CG_HOOK_DISABLE": "1"}).stdout.strip() == ""
    assert _hook({"garbage": True}).returncode == 0


def test_incremental_changed_mode_only_scans_changes(tmp_path):
    repo = tmp_path / "r"
    shutil.copytree(FIX / "safe_odoo", repo)
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    for cmd in (["init", "-q"], ["add", "."], ["commit", "-qm", "base"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env)
    shutil.copy(FIX / "vuln_python" / "app.py", repo / "new_app.py")
    res = scan(repo, mode="changed")
    assert res["meta"]["files_scanned"] == 1
    assert {f.path for f in res["findings"] if f.rule_id != "CG-CFG-001"} == {"new_app.py"}


def test_cli_smoke():
    for args in (["rules"], ["explain", "CG-ODOO-SUDO-001"], ["tools"], ["registry"]):
        r = subprocess.run(CG + args, capture_output=True, text=True)
        assert r.returncode == 0, (args, r.stderr)
    r = subprocess.run(CG + ["explain", "CG-ODOO-SUDO-001"], capture_output=True, text=True)
    assert "Verify before confirming" in r.stdout and "eu_gdpr" in r.stdout


def test_xml_with_entities_is_not_parsed():
    from cg.analyzers.odoo_data import analyze_xml
    bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaa"><!ENTITY b "&a;&a;&a;&a;">]><odoo>&b;</odoo>'
    assert analyze_xml("x.xml", bomb, {}) == []


def test_remediation_closes_findings_and_keeps_others(tmp_path):
    """Apply the documented smallest-safe fixes to a copy and verify the re-scan closes exactly those findings."""
    proj = tmp_path / "m"
    shutil.copytree(FIX / "vuln_odoo" / "vuln_portal", proj)
    ctrl = proj / "controllers" / "main.py"
    src = ctrl.read_text()
    before = {(f.rule_id, f.line) for f in scan(proj)["findings"]}
    assert any(r == "CG-PY-SQLI-001" for r, _ in before) and any(r == "CG-ODOO-SUDO-001" for r, _ in before)
    src = src.replace(
        '''request.env.cr.execute("SELECT id, name FROM res_partner WHERE name ILIKE '%%%s%%'" % q)''',
        '''request.env.cr.execute("SELECT id, name FROM res_partner WHERE name ILIKE %s", ("%" + q + "%",))''')
    src = src.replace(
        '''invoice = request.env["account.move"].sudo().browse(invoice_id)''',
        '''invoice = request.env["account.move"].browse(invoice_id)\n        invoice.check_access("read")''')
    ctrl.write_text(src)
    after = scan(proj)["findings"]
    rules_ctrl = {f.rule_id for f in after if f.path.endswith("controllers/main.py")}
    assert "CG-ODOO-SUDO-001" not in rules_ctrl
    assert not [f for f in after if f.rule_id == "CG-PY-SQLI-001" and f.path.endswith("controllers/main.py")]
    assert {"CG-PY-CMDI-001", "CG-PY-DESER-001"} <= rules_ctrl      # unrelated findings remain open
