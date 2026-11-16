"""Optional external scanners: detection, local execution, normalization.

Policy:
  * Never installs anything. `cg.py tools` prints optional install commands.
  * Runs only local analysis by default. Tools that contact the network (pip-audit -> vulnerability
    DB, trivy -> DB download) run only with --allow-network; they send package names/versions,
    never source code.
  * Semgrep runs with --metrics=off and the bundled local rules only (no registry download).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import SKILL_DIR
from .model import Finding

TOOLS = {
    "semgrep": dict(network=False, install="python3 -m pip install --user semgrep   # or: pipx install semgrep",
                    purpose="Custom Odoo/Python/JS rules (rules/semgrep)"),
    "bandit": dict(network=False, install="pipx install bandit", purpose="Python security linter"),
    "ruff": dict(network=False, install="pipx install ruff", purpose="Python lint incl. flake8-bandit (S) rules"),
    "gitleaks": dict(network=False, install="https://github.com/gitleaks/gitleaks/releases (verify checksum)",
                     purpose="Secret detection"),
    "detect-secrets": dict(network=False, install="pipx install detect-secrets", purpose="Secret detection"),
    "eslint": dict(network=False, install="npm i -D eslint eslint-plugin-security (per project)",
                   purpose="JS/TS security lint (runs only if the project has an ESLint config)"),
    "checkov": dict(network=False, install="pipx install checkov", purpose="IaC misconfiguration (run with --skip-download)"),
    "pip-audit": dict(network=True, install="pipx install pip-audit",
                      purpose="Python dependency CVEs (queries PyPI/OSV with package names)"),
    "trivy": dict(network=True, install="https://aquasecurity.github.io/trivy (verify signature)",
                  purpose="Container/IaC/dependency scanning (downloads vulnerability DB)"),
}


def detect() -> dict:
    return {name: shutil.which(name) for name in TOOLS}


def _run(cmd, cwd, timeout=600):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return -1, "", str(e)


def _f(tool, rid, sev, conf, path, line, msg, cwe=None, snippet=""):
    return Finding(rule_id=f"EXT-{tool}-{rid}", title=msg[:120], severity=sev, confidence=conf, path=path,
                   line=int(line or 1), message=msg, snippet=snippet or "", cwe=cwe or [], tool=tool,
                   category="security")


SEV_MAP = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
           "CRITICAL": "CRITICAL", "UNKNOWN": "MEDIUM"}


def _rel(root: Path, p: str) -> str:
    try:
        return Path(p).resolve().relative_to(root).as_posix()
    except ValueError:
        return p


def run_all(root: Path, allow_network=False, only=None, excludes=()) -> tuple:
    """Returns (findings, status dict tool -> 'ran'|'unavailable'|'skipped: reason'|'error: ...')."""
    found = detect()
    status, out = {}, []
    for tool, path in found.items():
        if only and tool not in only:
            continue
        if not path:
            status[tool] = "unavailable"
            continue
        if TOOLS[tool]["network"] and not allow_network:
            status[tool] = "skipped: requires network (use --allow-network)"
            continue
        try:
            res, st = RUNNERS[tool](root)
            out += res
            status[tool] = st
        except Exception as e:  # noqa: BLE001
            status[tool] = f"error: {e}"
    import fnmatch
    from .scanner import SKIP_DIRS, SKIP_PATH_RE
    kept = []
    for f in out:
        parts = set(f.path.split("/")[:-1])
        if parts & SKIP_DIRS or SKIP_PATH_RE.search(f.path) or any(fnmatch.fnmatch(f.path, p) for p in excludes):
            continue
        kept.append(f.finalize())
    return kept, status


def _bandit(root):
    rc, so, se = _run(["bandit", "-r", ".", "-f", "json", "-q", "-x",
                       "./node_modules,./.venv,./venv,./.git,./tests/fixtures"], root)
    data = json.loads(so or "{}")
    res = [_f("bandit", r["test_id"], SEV_MAP.get(r["issue_severity"], "MEDIUM"), r["issue_confidence"].lower(),
              _rel(root, r["filename"]), r["line_number"], r["issue_text"],
              [f"CWE-{r['issue_cwe']['id']}"] if r.get("issue_cwe") else [], r.get("code", ""))
           for r in data.get("results", [])]
    return res, f"ran ({len(res)} results)"


def _semgrep(root):
    rules = SKILL_DIR / "rules" / "semgrep"
    rc, so, se = _run(["semgrep", "scan", "--config", str(rules), "--metrics=off", "--disable-version-check",
                       "--json", "--quiet", "."], root, timeout=900)
    data = json.loads(so or "{}")
    res = []
    for r in data.get("results", []):
        md = r.get("extra", {}).get("metadata", {})
        cwe = md.get("cwe", [])
        cwe = [c.split(":")[0] for c in (cwe if isinstance(cwe, list) else [cwe])]
        res.append(_f("semgrep", r["check_id"].split(".")[-1], SEV_MAP.get(r["extra"].get("severity", "WARNING")),
                      str(md.get("confidence", "medium")).lower(), _rel(root, r["path"]), r["start"]["line"],
                      r["extra"].get("message", ""), cwe, r["extra"].get("lines", "")))
    errs = data.get("errors") or []
    return res, f"ran ({len(res)} results{', %d errors' % len(errs) if errs else ''})"


def _ruff(root):
    rc, so, se = _run(["ruff", "check", "--select", "S", "--ignore", "S101", "--output-format", "json", "--exit-zero",
                       "--no-cache", "."], root)
    data = json.loads(so or "[]")
    res = [_f("ruff", r["code"], "MEDIUM" if r["code"] in ("S102", "S301", "S307", "S602", "S608", "S506") else "LOW",
              "medium", _rel(root, r["filename"]), r["location"]["row"], f"{r['code']}: {r['message']}")
           for r in data]
    return res, f"ran ({len(res)} results)"


def _gitleaks(root):
    with tempfile.TemporaryDirectory() as td:
        rep = Path(td) / "gl.json"
        _run(["gitleaks", "detect", "--source", ".", "--no-git", "--redact", "--no-banner", "--report-format", "json",
              "--report-path", str(rep), "--exit-code", "0"], root)
        data = json.loads(rep.read_text()) if rep.exists() else []
    res = [_f("gitleaks", r.get("RuleID", "secret"), "HIGH", "medium", r.get("File", ""), r.get("StartLine", 1),
              f"Secret detected: {r.get('Description', '')}", ["CWE-798"]) for r in data]
    return res, f"ran ({len(res)} results)"


def _detect_secrets(root):
    rc, so, se = _run(["detect-secrets", "scan", "."], root)
    data = json.loads(so or "{}")
    res = [_f("detect-secrets", s["type"].replace(" ", "_"), "HIGH", "low", fn, s.get("line_number", 1),
              f"Potential secret: {s['type']}", ["CWE-798"])
           for fn, items in (data.get("results") or {}).items() for s in items]
    return res, f"ran ({len(res)} results)"


def _eslint(root):
    if not any((root / n).exists() for n in ("eslint.config.js", "eslint.config.mjs", ".eslintrc", ".eslintrc.js",
                                              ".eslintrc.json", ".eslintrc.cjs")):
        return [], "skipped: no ESLint config in project"
    rc, so, se = _run(["eslint", "-f", "json", "."], root)
    res = []
    for fobj in json.loads(so or "[]"):
        for m in fobj.get("messages", []):
            if m.get("ruleId") and ("security" in m["ruleId"] or m["ruleId"] in ("no-eval", "no-implied-eval",
                                                                                 "no-new-func")):
                res.append(_f("eslint", m["ruleId"], "MEDIUM", "medium", _rel(root, fobj["filePath"]),
                              m.get("line", 1), m.get("message", "")))
    return res, f"ran ({len(res)} security results)"


def _checkov(root):
    rc, so, se = _run(["checkov", "-d", ".", "-o", "json", "--quiet", "--compact", "--skip-download"], root, 900)
    data = json.loads(so or "{}")
    blocks = data if isinstance(data, list) else [data]
    res = []
    for b in blocks:
        for c in (b.get("results") or {}).get("failed_checks", []):
            res.append(_f("checkov", c["check_id"], SEV_MAP.get(str(c.get("severity") or "MEDIUM").upper(), "MEDIUM"),
                          "medium", c.get("file_path", "").lstrip("/"), (c.get("file_line_range") or [1])[0],
                          c.get("check_name", "")))
    return res, f"ran ({len(res)} results)"


def _pip_audit(root):
    reqs = sorted(root.glob("**/requirements*.txt"))[:10]
    if not reqs:
        return [], "skipped: no requirements*.txt"
    res = []
    for r in reqs:
        rc, so, se = _run(["pip-audit", "-r", str(r), "-f", "json", "--progress-spinner", "off"], root)
        try:
            data = json.loads(so or "{}")
        except json.JSONDecodeError:
            continue
        for d in data.get("dependencies", []):
            for v in d.get("vulns", []):
                res.append(_f("pip-audit", v["id"], "HIGH", "high", _rel(root, str(r)), 1,
                              f"{d['name']} {d.get('version')} vulnerable ({v['id']}); fix: "
                              f"{', '.join(v.get('fix_versions') or ['none'])}", ["CWE-1395"]))
    return res, f"ran ({len(res)} results)"


def _trivy(root):
    rc, so, se = _run(["trivy", "fs", "--scanners", "vuln,misconfig", "--format", "json", "--quiet", "."], root, 900)
    data = json.loads(so or "{}")
    res = []
    for r in data.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            res.append(_f("trivy", v["VulnerabilityID"], SEV_MAP.get(v.get("Severity", "MEDIUM"), "MEDIUM"), "high",
                          r.get("Target", ""), 1, f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('Title', '')}"))
        for m in r.get("Misconfigurations") or []:
            res.append(_f("trivy", m.get("ID", "misconfig"), SEV_MAP.get(m.get("Severity", "MEDIUM"), "MEDIUM"),
                          "medium", r.get("Target", ""), (m.get("CauseMetadata") or {}).get("StartLine", 1),
                          m.get("Title", "")))
    return res, f"ran ({len(res)} results)"


RUNNERS = {"bandit": _bandit, "semgrep": _semgrep, "ruff": _ruff, "gitleaks": _gitleaks,
           "detect-secrets": _detect_secrets, "eslint": _eslint, "checkov": _checkov, "pip-audit": _pip_audit,
           "trivy": _trivy}
