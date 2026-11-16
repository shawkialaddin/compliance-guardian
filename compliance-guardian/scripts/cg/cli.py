"""compliance-guardian command line interface."""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import shutil
import sys
from pathlib import Path

from . import VERSION, catalog, external, gate, registry, reports
from .config import SKILL_DIR, as_date, find_project_root, load_config, load_data, load_optional
from .model import SEV_RANK, sort_findings
from .sarif import to_sarif
from .scanner import apply_triage_and_exceptions, scan


def _scan(args, mode=None):
    target = Path(args.path).resolve()
    res = scan(target, mode=mode or getattr(args, "mode", "full"), files=getattr(args, "files", None),
               since=getattr(args, "since", None), min_severity=getattr(args, "min_severity", "INFO"))
    ext_status = None
    if getattr(args, "external", False):
        root = Path(res["meta"]["root"])
        excludes = tuple(((res["config"] or {}).get("scan") or {}).get("exclude") or ())
        ext, ext_status = external.run_all(root, allow_network=getattr(args, "allow_network", False), excludes=excludes)
        cfg = res["config"]
        apply_triage_and_exceptions(ext, cfg, load_optional(root, "compliance/triage.yaml"))
        res["findings"] = sort_findings(res["findings"] + ext)
        res["meta"]["rules_run"] = sorted(set(res["meta"]["rules_run"]) |
                                          {f"EXT-{t}-*" for t, st in ext_status.items() if st.startswith("ran")})
        res["meta"]["external_tools"] = ext_status
    return res, ext_status


def _context(res):
    root = Path(res["meta"]["root"])
    sources, frameworks = registry.load_registry()
    appl = registry.applicability(res["config"], frameworks)
    evidence = load_optional(root, "compliance/evidence.yaml")
    matrix = registry.compute_matrix(frameworks, appl, res["findings"], set(res["meta"]["rules_run"]), evidence,
                                     res["meta"])
    approvals = load_optional(root, "compliance/approvals.yaml")
    triage = load_optional(root, "compliance/triage.yaml")
    g = gate.evaluate(res["findings"], res["config"], matrix, appl, approvals, triage)
    return root, sources, appl, matrix, g


def cmd_scan(args):
    res, ext_status = _scan(args)
    fs = res["findings"]
    if args.format == "json":
        out = json.dumps(dict(meta=res["meta"], external_tools=ext_status, findings=[f.to_dict() for f in fs],
                              inventory=res["inventory"]), indent=2, default=str)
    elif args.format == "sarif":
        out = json.dumps(to_sarif(fs, res["meta"]), indent=2)
    else:
        m = res["meta"]
        lines = [f"compliance-guardian {VERSION} | mode={m['mode']} files={m['files_scanned']} "
                 f"odoo={m.get('odoo_version') or 'n/a'} config={'yes' if m['config_present'] else 'NO'}"]
        if ext_status:
            lines.append("external: " + ", ".join(f"{k}={v}" for k, v in ext_status.items()))
        for f in fs:
            flag = f" [{f.verification}]" if f.verification != "candidate" else ""
            exc = f" [exception {f.exception_id}]" if f.exception_id else ""
            lines.append(f"{f.id} {f.severity:<8} {f.confidence:<6} {f.rule_id:<22} {f.path}:{f.line}  {f.message}"
                         f"{flag}{exc}  (fp {f.fingerprint})")
        counts = {}
        for f in fs:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        lines.append("summary: " + (", ".join(f"{k}={counts[k]}" for k in sorted(counts, key=SEV_RANK.get)) or
                                    "no findings") + " | all results are CANDIDATES until contextually verified")
        out = "\n".join(lines)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(out + "\n")
        print(f"written: {args.out}")
    else:
        print(out)
    if args.fail_on:
        lim = SEV_RANK[args.fail_on]
        bad = [f for f in fs if SEV_RANK.get(f.severity, 9) <= lim and f.verification not in ("false_positive", "fixed")
               and not f.exception_id]
        return 1 if bad else 0
    return 0


def cmd_report(args):
    res, ext_status = _scan(args)
    root, sources, appl, matrix, g = _context(res)
    out = Path(args.out) if args.out else root / "compliance" / "reports"
    names = reports.write_all(out, res, matrix, appl, g, sources, ext_status)
    print(f"reports written to {out}: {', '.join(names)}")
    print(f"technical gate: {g['technical_gate']} | evidence: {g['evidence_status']} | "
          f"legal pending: {sum(1 for v in g['legal'].values() if v == 'PENDING')} | deployment: {g['deployment'][:40]}")
    return 0


def cmd_release(args):
    args.mode = "full"
    res, ext_status = _scan(args)
    root, sources, appl, matrix, g = _context(res)
    out = Path(args.out) if args.out else root / "compliance" / "reports"
    reports.write_all(out, res, matrix, appl, g, sources, ext_status)
    print(f"1. technical security gate : {g['technical_gate']}  (blockers={len(g['blockers'])}, "
          f"untriaged={len(g['triage_needed'])}, risk-decisions-needed={len(g['risk_decision_needed'])})")
    print(f"2. regulatory evidence     : {g['evidence_status']} {g['evidence_counts']}")
    print(f"3. legal approval          : {g['legal'] or 'none required per config'}")
    print(f"4. deployment authorization: {g['deployment']}")
    print(f"reports: {out}")
    print("NOTE: a technical gate result is not a legal certification.")
    code = g["exit_code"]
    if args.strict and g["technical_gate"] == "CONDITIONAL":
        code = 1
    return code


def cmd_applicability(args):
    root = find_project_root(Path(args.path))
    cfg, errs = load_config(root)
    _, frameworks = registry.load_registry()
    appl = registry.applicability(cfg, frameworks)
    for e in errs:
        print(f"config error: {e}")
    for fid, a in appl.items():
        print(f"{fid:<16} {a['status']:<24} legal_review={'REQUIRED' if a['legal_review'] else 'no':<9} "
              f"{' | '.join(a['reasons'])}")
    print("Engineering indication only - not a legal determination.")
    return 0


def cmd_tools(args):
    found = external.detect()
    for name, path in found.items():
        meta = external.TOOLS[name]
        net = " [network]" if meta["network"] else ""
        print(f"{name:<15} {'installed: ' + path if path else 'MISSING':<45}{net} {meta['purpose']}")
        if not path:
            print(f"{'':<15} optional install: {meta['install']}")
    print("Nothing is installed automatically.")
    return 0


def cmd_rules(args):
    if args.format == "json":
        print(json.dumps(list(catalog.R.values()), indent=2))
        return 0
    print("| Rule | Severity | Confidence | CWE | OWASP | Title |\n|---|---|---|---|---|---|")
    for r in catalog.R.values():
        print(f"| {r['id']} | {r['severity']} | {r['confidence']} | {', '.join(r['cwe'])} | {', '.join(r['owasp'])} | "
              f"{r['title']} |")
    return 0


def cmd_explain(args):
    key = args.key
    r = catalog.R.get(key)
    if r is None:  # finding id / fingerprint from last findings.json
        root = find_project_root(Path(args.path))
        fj = root / "compliance" / "reports" / "findings.json"
        if fj.exists():
            for f in json.loads(fj.read_text()).get("findings", []):
                if key in (f["id"], f["fingerprint"]):
                    print(json.dumps({k: f[k] for k in ("id", "rule_id", "severity", "confidence", "path", "line",
                                                         "message", "snippet", "verification")}, indent=2))
                    r = catalog.R.get(f["rule_id"])
                    break
    if r is None:
        print(f"unknown rule/finding: {key}")
        return 1
    print(f"{r['id']}: {r['title']}\nseverity={r['severity']} confidence={r['confidence']} cwe={r['cwe']} "
          f"owasp={r['owasp']}\n\nRemediation: {r['remediation']}\n\nVerify before confirming: {r['verify']}")
    if r["example_fix"]:
        print(f"\nExample:\n{r['example_fix']}")
    _, frameworks = registry.load_registry()
    maps = [(fid, c["id"], c.get("reference"), c.get("reference_status"), er["id"])
            for fid, fw in frameworks.items() for c in fw.get("controls", [])
            for er in c.get("engineering_requirements", []) if r["id"] in er.get("rules", [])]
    if maps:
        print("\nMapped controls (applicability depends on project configuration):")
        for m in maps:
            print(f"  - {m[0]} {m[1]} {m[2]} [{m[3]}] -> {m[4]}")
    return 0


def cmd_triage(args):
    root = find_project_root(Path(args.path))
    p = root / "compliance" / "triage.yaml"
    data = load_optional(root, "compliance/triage.yaml") or {}
    data.setdefault("findings", {})
    entry = dict(verdict=args.verdict, rationale=args.rationale, reviewer=args.reviewer,
                 date=_dt.date.today().isoformat())
    if args.severity:
        entry["severity"] = args.severity
    if args.risk_decision:
        entry["risk_decision"] = args.risk_decision
    data["findings"][args.fingerprint] = entry
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        import yaml
        p.write_text(yaml.safe_dump(data, sort_keys=True, allow_unicode=True))
    except ImportError:
        p.with_suffix(".json").write_text(json.dumps(data, indent=2))
    print(f"recorded {args.verdict} for {args.fingerprint} in {p}")
    return 0


def cmd_registry(args):
    sources, frameworks = registry.load_registry()
    today = _dt.date.today()
    stale_days = args.stale_days
    print(f"registry version {sources.get('registry_version')} (baseline locked: {sources.get('baseline_locked')})")
    for s in sources.get("sources", []):
        v = as_date(s.get("verified_on"))
        age = (today - v).days if v else None
        flag = "STALE" if age is None or age > stale_days else "ok"
        print(f"{s['id']:<28} {s.get('verification', '?'):<18} verified {s.get('verified_on')} ({age}d) {flag:<5} "
              f"{s.get('document')} {s.get('edition', '')}")
    n_unv = sum(1 for fw in frameworks.values() for c in fw.get("controls", [])
                if c.get("reference_status") != "VERIFIED")
    print(f"controls with UNVERIFIED references: {n_unv}")
    return 0


def cmd_init(args):
    root = Path(args.path).resolve()
    dst = root / ".compliance-guardian.yaml"
    if dst.exists() and not args.force:
        print(f"{dst} exists; not overwriting (use --force)")
        return 1
    tpl = (SKILL_DIR / "templates" / "compliance-guardian.example.yaml").read_text()
    if args.profile:
        tpl = tpl.replace("profiles: []", "profiles: [" + ", ".join(args.profile) + "]")
    dst.write_text(tpl)
    print(f"created {dst} - fill in the processing facts; leave unknowns empty rather than guessing")
    for ci in args.ci or []:
        src = SKILL_DIR / "templates" / "ci" / {"github": "github-actions.yml", "gitlab": "gitlab-ci.yml"}[ci]
        target = root / (".github/workflows/compliance-guardian.yml" if ci == "github" else ".gitlab-ci.compliance.yml")
        if target.exists():
            print(f"{target} exists; skipped")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, target)
        print(f"created {target}")
    if args.pre_commit:
        target = root / ".pre-commit-config.yaml"
        if target.exists():
            print(f"{target} exists; merge templates/ci/pre-commit-config.yaml manually")
        else:
            shutil.copy(SKILL_DIR / "templates" / "ci" / "pre-commit-config.yaml", target)
            print(f"created {target}")
    return 0


def cmd_vendor(args):
    dst = Path(args.dest).resolve()
    for sub in ("scripts", "registry", "rules", "schema", "profiles", "templates"):
        shutil.copytree(SKILL_DIR / sub, dst / sub, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    print(f"vendored scanner into {dst} (run: python3 {dst}/scripts/cg.py scan .)")
    return 0


def cmd_validate_config(args):
    root = find_project_root(Path(args.path))
    cfg, errs = load_config(root)
    if cfg is None and not errs:
        print("no .compliance-guardian.yaml found")
        return 1
    for e in errs:
        print(f"ERROR {e}")
    print("valid" if not errs else f"{len(errs)} error(s)")
    return 1 if errs else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cg.py", description=f"compliance-guardian {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, scan_opts=True):
        p.add_argument("path", nargs="?", default=".")
        if scan_opts:
            p.add_argument("--mode", choices=["full", "changed"], default="full")
            p.add_argument("--files", nargs="+")
            p.add_argument("--since", help="git ref for --mode changed (default HEAD)")
            p.add_argument("--min-severity", choices=list(SEV_RANK), default="INFO")
            p.add_argument("--external", action="store_true", help="also run installed external scanners locally")
            p.add_argument("--allow-network", action="store_true", help="permit external tools that contact the network")
        return p

    p = common(sub.add_parser("scan", help="scan and print findings"))
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("--out")
    p.add_argument("--fail-on", choices=list(SEV_RANK))
    p.set_defaults(fn=cmd_scan)
    p = common(sub.add_parser("report", help="write compliance/reports/*"))
    p.add_argument("--out")
    p.set_defaults(fn=cmd_report)
    p = common(sub.add_parser("release", help="full scan + reports + 4-dimension release gate"))
    p.add_argument("--out")
    p.add_argument("--strict", action="store_true", help="fail on CONDITIONAL too")
    p.set_defaults(fn=cmd_release)
    common(sub.add_parser("applicability", help="framework applicability indication"), False).set_defaults(
        fn=cmd_applicability)
    sub.add_parser("tools", help="detect optional external scanners").set_defaults(fn=cmd_tools)
    p = sub.add_parser("rules", help="list detection rules")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.set_defaults(fn=cmd_rules)
    p = sub.add_parser("explain", help="explain a rule id, finding id or fingerprint")
    p.add_argument("key")
    p.add_argument("--path", default=".")
    p.set_defaults(fn=cmd_explain)
    p = sub.add_parser("triage", help="record a reviewer verdict for a finding fingerprint")
    p.add_argument("fingerprint")
    p.add_argument("--verdict", required=True, choices=["confirmed", "false_positive", "fixed"])
    p.add_argument("--rationale", required=True)
    p.add_argument("--reviewer", required=True)
    p.add_argument("--severity", choices=list(SEV_RANK))
    p.add_argument("--risk-decision")
    p.add_argument("--path", default=".")
    p.set_defaults(fn=cmd_triage)
    p = sub.add_parser("registry", help="show regulatory source registry and staleness")
    p.add_argument("--stale-days", type=int, default=180)
    p.set_defaults(fn=cmd_registry)
    p = sub.add_parser("init", help="create .compliance-guardian.yaml (+ optional CI templates)")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--profile", action="append", help="profile name(s) from profiles/")
    p.add_argument("--ci", action="append", choices=["github", "gitlab"])
    p.add_argument("--pre-commit", action="store_true")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("vendor", help="copy the scanner into a repo path for CI use")
    p.add_argument("dest")
    p.set_defaults(fn=cmd_vendor)
    common(sub.add_parser("validate-config", help="validate .compliance-guardian.yaml"), False).set_defaults(
        fn=cmd_validate_config)
    sub.add_parser("hook", help="Claude Code PostToolUse hook entry (reads JSON on stdin)").set_defaults(
        fn=lambda a: __import__("cg.hook", fromlist=["main"]).main())
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
