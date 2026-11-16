"""File discovery (full / changed / explicit), analyzer dispatch, triage + exception application."""
from __future__ import annotations

import datetime as _dt
import fnmatch
import os
import re
import subprocess
import uuid
from pathlib import Path

from . import VERSION, catalog
from .analyzers import make, odoo_data, privacy, python_ast, textual
from .config import as_date, load_config, load_optional, odoo_version
from .model import SEV_RANK, sort_findings

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build", ".tox", ".mypy_cache",
             ".pytest_cache", "site-packages", ".idea", ".vscode", "compliance", ".compliance-guardian-cache"}
SKIP_PATH_RE = re.compile(r"(^|/)(static/lib|static/src/lib|vendor|third_party|\.min\.)|\.(lock|map)$|"
                          r"(^|/)package-lock\.json$|(^|/)yarn\.lock$")
MAX_SIZE = 2 * 1024 * 1024
JS_EXT = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".dart")
CFG_EXT = (".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env")

# analyzer -> rule ids it can produce (for "rules executed" evidence)
ANALYZER_RULES = {
    "python": [r for r in catalog.R if r.startswith(("CG-PY-", "CG-ODOO-SUDO",
               "CG-ODOO-AUTH", "CG-ODOO-CSRF", "CG-ODOO-CORS", "CG-ODOO-UPLOAD", "CG-ODOO-XSS-001", "CG-ODOO-XSS-003",
               "CG-ODOO-RATE", "CG-ODOO-INFO", "CG-ODOO-COMPAT"))],
    "privacy": ["CG-PRIV-001", "CG-ODOO-PRIV-002"],
    "xml": ["CG-ODOO-XSS-002", "CG-ODOO-RULE-001", "CG-ODOO-RULE-002", "CG-ODOO-GROUP-001", "CG-ODOO-VIEW-001"],
    "acl": ["CG-ODOO-ACL-001", "CG-ODOO-ACL-002", "CG-ODOO-ACL-003"],
    "manifest": ["CG-ODOO-MANIFEST-001", "CG-ODOO-HOOK-001"],
    "odoo_conf": ["CG-ODOO-CONF-001", "CG-ODOO-CONF-002", "CG-ODOO-CONF-003"],
    "js": ["CG-JS-XSS-001", "CG-JS-XSS-002", "CG-JS-EVAL-001", "CG-JS-STORAGE-001", "CG-JS-TLS-001", "CG-JS-CORS-001"],
    "secrets": ["CG-SEC-001", "CG-SEC-002", "CG-SEC-003"],
    "docker": ["CG-IAC-DOCKER-001", "CG-IAC-DOCKER-002", "CG-IAC-DOCKER-003", "CG-IAC-DOCKER-004"],
    "compose": ["CG-IAC-COMPOSE-001", "CG-IAC-COMPOSE-002"],
    "gha": ["CG-CI-001", "CG-CI-002"],
}


def _git(root: Path, *args) -> list:
    try:
        out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30, check=False)
        return [ln for ln in out.stdout.splitlines() if ln.strip()] if out.returncode == 0 else []
    except (OSError, subprocess.SubprocessError):
        return []


def discover(root: Path, mode: str, files=None, since=None, excludes=()) -> list:
    if files:
        cand = []
        for f in files:
            p = Path(f)
            p = p if p.is_absolute() else (Path.cwd() / p)
            if p.is_dir():
                cand += [q for q in p.rglob("*") if q.is_file()]
            elif p.exists():
                cand.append(p)
        cand = [c.resolve() for c in cand]
    elif mode == "changed":
        names = set(_git(root, "diff", "--name-only", since or "HEAD")) | set(_git(root, "diff", "--name-only",
                                                                                   "--cached")) | \
            set(_git(root, "ls-files", "-o", "--exclude-standard"))
        cand = [root / n for n in names if (root / n).is_file()]
    else:
        names = _git(root, "ls-files", "-co", "--exclude-standard")
        if names:
            cand = [root / n for n in names if (root / n).is_file()]
        else:
            cand = []
            for dp, dns, fns in os.walk(root):
                dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".") or d in (".github",)]
                cand += [Path(dp) / f for f in fns]
    out = []
    for p in cand:
        try:
            rel = p.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = p.as_posix()
        parts = set(rel.split("/")[:-1])
        if parts & SKIP_DIRS or SKIP_PATH_RE.search(rel):
            continue
        if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
            continue
        try:
            if p.stat().st_size > MAX_SIZE:
                continue
        except OSError:
            continue
        out.append((p, rel))
    return sorted(set(out), key=lambda x: x[1])


def analyze_file(p: Path, rel: str, ctx: dict, inventory: list, ran: set) -> list:
    name = p.name
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if "\x00" in text[:4096]:
        return []
    out = []
    low = name.lower()
    if low.endswith(".py"):
        out += python_ast.analyze(rel, text, ctx)
        ran.add("python")
        out += privacy.analyze_python(rel, text, ctx, inventory)
        ran.add("privacy")
        out += textual.analyze_secrets(rel, text, ctx)
        ran.add("secrets")
        if name in ("__manifest__.py", "__openerp__.py"):
            out += odoo_data.analyze_manifest(rel, text, ctx)
            ran.add("manifest")
        if privacy.has_retention_signal(text):
            ctx["_retention_signal"] = True
    elif low.endswith(".xml"):
        out += odoo_data.analyze_xml(rel, text, ctx)
        out += textual.analyze_secrets(rel, text, ctx)
        ran.update({"xml", "secrets"})
        if privacy.has_retention_signal(text):
            ctx["_retention_signal"] = True
    elif low.endswith(".csv") and "perm_read" in text[:500]:
        out += odoo_data.analyze_access_csv(rel, text, ctx)
        ran.add("acl")
        ctx.setdefault("_acl_models", set()).update(re.findall(r",\s*(?:\w+\.)?model_([\w]+)\s*,", text))
    elif low.endswith(JS_EXT):
        out += textual.analyze_js(rel, text, ctx)
        out += textual.analyze_secrets(rel, text, ctx)
        ran.update({"js", "secrets"})
    elif low.startswith("dockerfile") or low.endswith(".dockerfile"):
        out += textual.analyze_dockerfile(rel, text, ctx)
        ran.add("docker")
    elif re.match(r"(docker-)?compose[\w.-]*\.ya?ml$", low):
        out += textual.analyze_compose(rel, text, ctx)
        ran.update({"compose", "secrets"})
    elif "/.github/workflows/" in f"/{rel}" and low.endswith((".yml", ".yaml")):
        out += textual.analyze_gha(rel, text, ctx)
        out += textual.analyze_secrets(rel, text, ctx, structured_config=True)
        ran.update({"gha", "secrets"})
    elif low.endswith((".conf", ".cfg")) and "[options]" in text:
        out += odoo_data.analyze_odoo_conf(rel, text, ctx)
        ran.add("odoo_conf")
    elif low.endswith(CFG_EXT) or re.fullmatch(r"\.env(\.[\w-]+)?", low):
        if low == ".compliance-guardian.yaml":
            return out
        out += textual.analyze_secrets(rel, text, ctx, structured_config=True)
        ran.add("secrets")
    elif low.endswith((".sh", ".bash", ".sql", ".php", ".rb", ".go", ".java", ".kt", ".swift", ".tf", ".pem", ".key")):
        out += textual.analyze_secrets(rel, text, ctx)
        ran.add("secrets")
    if "_python_models" not in ctx:
        ctx["_python_models"] = {}
    if low.endswith(".py"):
        for m in re.finditer(r"^\s+_name\s*=\s*['\"]([\w.]+)['\"]", text, re.M):
            ctx["_python_models"].setdefault(m.group(1), (rel, text.count("\n", 0, m.start()) + 1))
    return out


def project_findings(root, cfg, cfg_errors, ctx, inventory, mode) -> list:
    out = []
    if cfg is None:
        out.append(make("CG-CFG-001", ".compliance-guardian.yaml", 1, "", "No .compliance-guardian.yaml: only "
                        "baseline checks applied; regulatory applicability unresolved"))
    for e in cfg_errors[:10]:
        out.append(make("CG-CFG-002", ".compliance-guardian.yaml", 1, "", e))
    if mode == "full":
        if inventory and not ctx.get("_retention_signal"):
            out.append(make("CG-PRIV-003", inventory[0]["path"], inventory[0]["line"], "",
                            f"{len(inventory)} personal-data field(s) found; no anonymization/retention/erasure "
                            "mechanism detected in scanned code"))
        acl = ctx.get("_acl_models")
        if acl is not None:
            for model, (path, line) in sorted(ctx.get("_python_models", {}).items()):
                if model.replace(".", "_") not in acl:
                    out.append(make("CG-ODOO-ACL-004", path, line, "", f"Model '{model}' has no ir.model.access entry"))
    if cfg:
        out += transfer_findings(cfg)
    return out


def transfer_findings(cfg) -> list:
    out = []
    subj = {str(c).upper() for c in cfg.get("data_subject_locations") or []}
    dest = set()
    for c in [*(cfg.get("transfer_destinations") or []), *(cfg.get("backup_countries") or [])]:
        dest.add(str(c.get("country") if isinstance(c, dict) else c).upper())
    host = cfg.get("hosting") or {}
    if host.get("country"):
        dest.add(str(host["country"]).upper())
    for sp in cfg.get("subprocessors") or []:
        if isinstance(sp, dict):
            for c in sp.get("countries") or []:
                dest.add(str(c).upper())
    for origin, label in (("SA", "Saudi PDPL (Art. 29 + Transfer Regulation)"),
                          ("EG", "Egypt PDPL Law 151/2020 (cross-border provisions)"),
                          ("EU", "GDPR Chapter V (Art. 44-49)")):
        from .registry import EU_EEA
        in_scope = (subj & EU_EEA) if origin == "EU" else ({origin} & subj)
        if not in_scope:
            continue
        outside = sorted(d for d in dest if (d not in EU_EEA if origin == "EU" else d != origin))
        if outside:
            out.append(make("CG-PRIV-005", ".compliance-guardian.yaml", 1, "",
                            f"Data subjects in {', '.join(sorted(in_scope))}; hosting/backup/subprocessor/transfer "
                            f"destinations include {', '.join(outside)} -> {label}: LEGAL_REVIEW_REQUIRED"))
    return out


def apply_triage_and_exceptions(findings, cfg, triage):
    tri = (triage or {}).get("findings") or {}
    today = _dt.date.today()
    excs = (cfg or {}).get("approved_exceptions") or []
    for f in findings:
        t = tri.get(f.fingerprint)
        if isinstance(t, dict):
            verdict = str(t.get("verdict", "")).lower()
            if verdict in ("confirmed", "false_positive", "fixed") and t.get("rationale"):
                f.verification = verdict
                f.triage_note = f"{t.get('rationale')} ({t.get('reviewer', 'unknown reviewer')}, {t.get('date', '')})"
                if t.get("severity") in SEV_RANK:
                    f.severity = t["severity"]
        for e in excs:
            if not isinstance(e, dict):
                continue
            match = e.get("fingerprint") == f.fingerprint or (
                e.get("rule_id") == f.rule_id and e.get("path") and fnmatch.fnmatch(f.path, e["path"]))
            if not match:
                continue
            exp = as_date(e.get("expires_on"))
            valid = bool(e.get("approved_by") and as_date(e.get("approved_on")) and exp and exp >= today and
                         e.get("justification"))
            if valid:
                f.exception_id = e.get("id", "EXC-?")
            else:
                f.context["exception_invalid"] = f"{e.get('id', 'EXC-?')}: missing approver/dates/justification or expired"
    return findings


def scan(target: Path, mode="full", files=None, since=None, min_severity="INFO"):
    root = target if target.is_dir() else target.parent
    from .config import find_project_root
    root = find_project_root(root)
    cfg, cfg_errors = load_config(root)
    scan_cfg = (cfg or {}).get("scan") or {}
    ctx = {"odoo_version": odoo_version(cfg)}
    excludes = tuple(scan_cfg.get("exclude") or ())
    scope = target.resolve()
    if scope.is_dir() and scope != root and not files:
        # an explicitly requested path overrides exclude patterns that cover it
        probe = scope.relative_to(root).as_posix() + "/__probe__"
        excludes = tuple(p for p in excludes if not fnmatch.fnmatch(probe, p))
    paths = discover(root, mode, files=files, since=since, excludes=excludes)
    if scope.is_dir() and scope != root and not files:
        paths = [(p, rel) for p, rel in paths if scope in p.resolve().parents]
        ctx["scope_prefix"] = scope.relative_to(root).as_posix() + "/"
    if ctx["odoo_version"] is None:
        ctx["odoo_version"] = _detect_odoo_version(paths)
    findings, inventory, ran = [], [], set()
    for p, rel in paths:
        findings += analyze_file(p, rel, ctx, inventory, ran)
    findings += project_findings(root, cfg, cfg_errors, ctx, inventory, mode)
    for f in findings:
        f.finalize()
    triage = load_optional(root, "compliance/triage.yaml")
    apply_triage_and_exceptions(findings, cfg, triage)
    floor = SEV_RANK.get(min_severity, 4)
    findings = [f for f in findings if SEV_RANK.get(f.severity, 4) <= floor]
    sort_findings(findings)
    rules_run = sorted({r for a in ran for r in ANALYZER_RULES.get(a, [])})
    meta = dict(scan_id=uuid.uuid4().hex[:12], tool="compliance-guardian", version=VERSION, mode=mode,
                root=str(root), started=_dt.datetime.now().isoformat(timespec="seconds"), files_scanned=len(paths),
                analyzers=sorted(ran), rules_run=rules_run, odoo_version=ctx["odoo_version"],
                config_present=cfg is not None, config_errors=cfg_errors)
    return dict(meta=meta, findings=findings, inventory=inventory, config=cfg)


def _detect_odoo_version(paths):
    import ast as _ast
    counts = {}
    for p, rel in paths:
        if p.name == "__manifest__.py":
            try:
                v = str(_ast.literal_eval(p.read_text(errors="replace")).get("version", ""))
            except Exception:  # noqa: BLE001
                continue
            m = re.match(r"^(\d{2})\.0\.", v)
            if m:
                counts[int(m.group(1))] = counts.get(int(m.group(1)), 0) + 1
    return max(counts, key=counts.get) if counts else None
