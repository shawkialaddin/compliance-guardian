"""Regulatory registry loading, applicability determination and control-matrix computation.

Applicability output is an *engineering indication*, never a legal determination:
  DECLARED_APPLICABLE      - project config records a legal/contractual determination (who, when)
  CONTRACTUAL              - declared as a contractual obligation
  INDICATED                - configuration facts suggest the framework may apply -> LEGAL_REVIEW_REQUIRED
  POSSIBLY_APPLICABLE      - weak/unknown scope signals -> LEGAL_REVIEW_REQUIRED
  NOT_INDICATED            - configuration provides no applicability signal (not a legal conclusion)
  DECLARED_NOT_APPLICABLE  - project config records a determination that it does not apply
  BASELINE                 - recommended engineering baseline (not a legal obligation)
  UNDETERMINED             - no project configuration
"""
from __future__ import annotations

from pathlib import Path

from .config import SKILL_DIR, as_date, load_data

EU_EEA = {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU",
          "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO", "EU"}
REG_DIR = SKILL_DIR / "registry"


def load_registry():
    sources = load_data(REG_DIR / "sources.yaml")
    frameworks = {}
    for p in sorted((REG_DIR / "controls").glob("*.yaml")):
        data = load_data(p)
        frameworks[data["framework"]] = data
    return sources, frameworks


def _countries(cfg, *keys):
    out = set()
    for k in keys:
        cur = cfg
        for part in k.split("."):
            cur = (cur or {}).get(part) if isinstance(cur, dict) else None
        if isinstance(cur, list):
            for c in cur:
                if isinstance(c, dict):
                    c = c.get("country")
                if c:
                    out.add(str(c).upper())
        elif isinstance(cur, str):
            out.add(cur.upper())
    return out


def applicability(cfg, frameworks: dict) -> dict:
    res = {}
    if not cfg:
        for fid, fw in frameworks.items():
            if fw.get("kind") == "baseline":
                res[fid] = dict(status="BASELINE", reasons=["Recommended engineering baseline"], legal_review=False)
            else:
                res[fid] = dict(status="UNDETERMINED", legal_review=True,
                                reasons=["No .compliance-guardian.yaml; applicability cannot be assessed"])
        return res

    declared = {}
    for d in cfg.get("regulatory_requirements") or []:
        if isinstance(d, dict) and d.get("framework"):
            declared[d["framework"]] = d
    contractual = {c.get("framework") if isinstance(c, dict) else c for c in cfg.get("contractual_requirements") or []}

    proc = _countries(cfg, "processing_countries", "hosting.country")
    subj = _countries(cfg, "data_subject_locations")
    cust = _countries(cfg, "customer_countries")
    org = cfg.get("organization") or {}
    cls = {str(x).lower() for x in (org.get("classification") or [])}
    sector = str(org.get("industry") or "").lower()
    role = {str(x).lower() for x in (cfg.get("processing_role") or [])}
    cloud = str(org.get("cloud_role") or "none").lower()
    gov_ksa = bool(cls & {"government", "government_affiliated", "cni"}) and ("SA" in proc | cust)
    handles_pd = bool(cfg.get("personal_data_categories") or cfg.get("sensitive_data_categories"))

    def put(fid, status, reasons, legal_review=True):
        res[fid] = dict(status=status, reasons=reasons, legal_review=legal_review)

    for fid, fw in frameworks.items():
        if fid in declared:
            d = declared[fid]
            st = str(d.get("status", "")).lower()
            who, when = d.get("determined_by"), d.get("determined_on")
            if st == "applicable":
                put(fid, "DECLARED_APPLICABLE", [f"Declared applicable by {who or 'UNKNOWN'} on {when or 'UNKNOWN'}: "
                                                 f"{d.get('basis', 'no basis recorded')}"],
                    legal_review=not (who and when))
                continue
            if st == "not_applicable":
                put(fid, "DECLARED_NOT_APPLICABLE", [f"Declared not applicable by {who or 'UNKNOWN'}: "
                                                     f"{d.get('basis', 'no basis recorded')}"],
                    legal_review=not (who and when))
                continue
            if st == "contractual":
                put(fid, "CONTRACTUAL", [f"Contractual obligation: {d.get('basis', '')}"], legal_review=False)
                continue
        if fid in contractual:
            put(fid, "CONTRACTUAL", ["Listed in contractual_requirements"], legal_review=False)
            continue
        if fw.get("kind") == "baseline":
            put(fid, "BASELINE", ["Recommended engineering baseline"], legal_review=False)
            continue

        if fid == "eu_gdpr":
            r = []
            if proc & EU_EEA:
                r.append(f"Processing/hosting in EU/EEA ({', '.join(sorted(proc & EU_EEA))}) - Art. 3(1) establishment test")
            if subj & EU_EEA:
                r.append(f"Data subjects in EU/EEA ({', '.join(sorted(subj & EU_EEA))}) - Art. 3(2) targeting/monitoring "
                         "test must be assessed")
            put(fid, "INDICATED" if r and handles_pd else ("POSSIBLY_APPLICABLE" if r else "NOT_INDICATED"),
                r or ["No EU/EEA processing or data subjects declared"], legal_review=bool(r))
        elif fid == "ksa_pdpl":
            r = []
            if "SA" in proc:
                r.append("Processing in Saudi Arabia")
            if "SA" in subj:
                r.append("Data subjects in Saudi Arabia (PDPL also covers processing outside KSA of residents' data - verify scope)")
            put(fid, "INDICATED" if r and handles_pd else ("POSSIBLY_APPLICABLE" if r else "NOT_INDICATED"),
                r or ["No KSA processing or data subjects declared"], legal_review=bool(r))
        elif fid in ("ksa_nca_ecc", "ksa_nca_dcc"):
            if gov_ksa:
                put(fid, "INDICATED", ["Organization/customer classified as government, government-affiliated or CNI "
                                       "in KSA (official scope per NCA document)"])
            else:
                put(fid, "NOT_INDICATED", ["Not indicated: NCA ECC/DCC scope is government entities, their affiliates "
                                           "and CNI operators - not every Saudi-located organization"], legal_review=False)
        elif fid == "ksa_nca_ccc":
            if cloud in ("provider", "tenant") and gov_ksa:
                put(fid, "INDICATED", [f"Cloud {cloud} serving a government/CNI context in KSA"])
            elif cloud == "provider" and "SA" in proc | cust:
                put(fid, "POSSIBLY_APPLICABLE", ["Cloud service provider operating in KSA - verify CCC scope"])
            else:
                put(fid, "NOT_INDICATED", ["No cloud provider/tenant role in a KSA government/CNI context"],
                    legal_review=False)
        elif fid == "ksa_nca_ncnicc":
            if ("SA" in proc | cust) and not gov_ksa and "private" in (cls or {"private"}):
                put(fid, "POSSIBLY_APPLICABLE", ["Private-sector non-CNI entity in KSA; NCNICC-1:2025 scope and "
                                                 "entity-size obligations not verified from official text (Arabic only)"])
            else:
                put(fid, "NOT_INDICATED", ["No KSA private-sector non-CNI signal"], legal_review=False)
        elif fid == "eg_pdpl":
            r = []
            if "EG" in proc:
                r.append("Processing in Egypt")
            if "EG" in subj:
                r.append("Data subjects in Egypt (Law 151/2020 territorial scope must be assessed)")
            put(fid, "INDICATED" if r and handles_pd else ("POSSIBLY_APPLICABLE" if r else "NOT_INDICATED"),
                r or ["No Egyptian processing or data subjects declared"], legal_review=bool(r))
        elif fid == "eg_cyber":
            if "EG" in proc | cust:
                r = ["Operations/customers in Egypt: Law 175/2018 obligations depend on whether the organization is a "
                     "'service provider' under the law"]
                if sector in ("telecom", "ict", "isp", "hosting"):
                    r.append(f"Sector '{sector}' may bring NTRA/sectoral requirements")
                put(fid, "POSSIBLY_APPLICABLE", r)
            else:
                put(fid, "NOT_INDICATED", ["No Egyptian operations declared"], legal_review=False)
        else:
            put(fid, "UNDETERMINED", ["No applicability logic for this framework"])
    for fid in cfg.get("_profile_frameworks") or []:
        if fid in res and res[fid]["status"] in ("NOT_INDICATED", "UNDETERMINED"):
            res[fid] = dict(status="POSSIBLY_APPLICABLE", legal_review=True,
                            reasons=res[fid]["reasons"] + ["Selected via project profile; legal applicability unconfirmed"])
    _ = role
    return res


ACTIVE = {"DECLARED_APPLICABLE", "CONTRACTUAL", "INDICATED", "POSSIBLY_APPLICABLE", "BASELINE", "UNDETERMINED"}


def compute_matrix(frameworks, appl, findings, rules_run, evidence, scan_meta):
    """Return list of matrix rows: framework/control/requirement with evidence-backed status."""
    def match(pattern, rid):
        return rid.startswith(pattern[:-1]) if pattern.endswith("*") else rid == pattern
    ev = {}
    for e in (evidence or {}).get("controls", []) or []:
        if isinstance(e, dict) and e.get("requirement"):
            ev[e["requirement"]] = e
    rows = []
    for fid, fw in frameworks.items():
        a = appl.get(fid, {})
        fst = a.get("status", "UNDETERMINED")
        for c in fw.get("controls", []):
            for er in c.get("engineering_requirements", []):
                row = dict(framework=fid, framework_name=fw.get("name"), obligation=fw.get("obligation_type"),
                           control=c["id"], reference=c.get("reference"),
                           reference_status=c.get("reference_status", "UNVERIFIED"), title=c.get("title"),
                           requirement_id=er["id"], requirement=er["requirement"],
                           verification=er.get("verification", "manual"), rules=er.get("rules", []),
                           tests=er.get("tests", []), source_files=[], evidence=[], status="NOT_TESTED", note="")
                if fst in ("NOT_INDICATED", "DECLARED_NOT_APPLICABLE"):
                    row["status"] = "NOT_APPLICABLE"
                    row["note"] = f"Framework {fst.lower().replace('_', ' ')} (see applicability)"
                    rows.append(row)
                    continue
                rule_hits = [f for f in findings if any(match(r, f.rule_id) for r in row["rules"])
                             and f.verification not in ("false_positive", "fixed")]
                row["source_files"] = sorted({f"{f.path}:{f.line}" for f in rule_hits})[:10]
                confirmed = [f for f in rule_hits if f.verification == "confirmed" and not f.exception_id]
                candidates = [f for f in rule_hits if f.verification == "candidate"]
                ran = [r for r in row["rules"] if r in rules_run]
                v = row["verification"]
                if v == "legal":
                    row["status"] = "LEGAL_REVIEW_REQUIRED"
                elif v == "manual":
                    row["status"] = "MANUAL_REVIEW_REQUIRED"
                elif confirmed:
                    row["status"] = "FAIL"
                    row["evidence"] = [f"{f.id} {f.rule_id} confirmed" for f in confirmed[:5]]
                elif candidates:
                    row["status"] = "MANUAL_REVIEW_REQUIRED"
                    row["note"] = f"{len(candidates)} candidate finding(s) require triage"
                elif not ran:
                    row["status"] = "NOT_TESTED"
                    row["note"] = "No automated rule for this requirement executed in this scan scope"
                else:
                    scope = f"scan {scan_meta.get('scan_id')} ({scan_meta.get('mode')}, {scan_meta.get('files_scanned')} files, " \
                            f"rules {', '.join(ran)}): 0 open findings"
                    row["evidence"] = [scope]
                    if v == "automated_full" and scan_meta.get("mode") == "full":
                        row["status"] = "PASS"
                    else:
                        row["status"] = "PARTIAL"
                        row["note"] = "Automated portion found no issues; manual verification outstanding" \
                            if v != "automated_full" else "Incremental scan only; run a full scan for PASS evidence"
                # recorded evidence (human review) may resolve manual/legal items
                rec = ev.get(row["requirement_id"])
                if rec:
                    st = str(rec.get("status", "")).upper()
                    refs = rec.get("evidence") or []
                    who = rec.get("reviewer")
                    if st in ("PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE") and refs and who and as_date(rec.get("date")):
                        if not (row["status"] == "FAIL" and st == "PASS"):
                            row["status"] = st
                        row["evidence"] = row["evidence"] + [f"{r} (reviewed by {who}, {rec.get('date')})" for r in refs]
                    else:
                        row["note"] = (row["note"] + "; " if row["note"] else "") + \
                            "evidence record ignored: requires status, evidence refs, reviewer and date"
                if fst in ("INDICATED", "POSSIBLY_APPLICABLE", "UNDETERMINED") and row["status"] == "PASS":
                    row["note"] = "Technical control verified; legal applicability still requires review"
                rows.append(row)
    return rows


def framework_sources(sources) -> dict:
    return {s["id"]: s for s in (sources or {}).get("sources", [])}


def registry_dir() -> Path:
    return REG_DIR
