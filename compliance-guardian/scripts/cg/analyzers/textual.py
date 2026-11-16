"""Regex-based analyzers: JS/TS/Dart, secrets in any text file, Dockerfile/compose, GitHub Actions."""
from __future__ import annotations

import re

from . import line_of, make

JS_RULES = [
    ("CG-JS-XSS-001", re.compile(r"\.(innerHTML|outerHTML)\s*\+?=\s*(?![\"'`]\s*[\"'`]\s*;?\s*$)(?![\"'][^\"'`$]*[\"']\s*;?\s*$)")),
    ("CG-JS-XSS-001", re.compile(r"\.insertAdjacentHTML\s*\(\s*[^,]+,\s*(?![\"'][^\"']*[\"']\s*\))")),
    ("CG-JS-XSS-001", re.compile(r"\bdocument\.write(ln)?\s*\(")),
    ("CG-JS-XSS-001", re.compile(r"dangerouslySetInnerHTML\s*=")),
    ("CG-JS-XSS-002", re.compile(r"\bmarkup\s*\(\s*(?![\"'][^\"'`]*[\"']\s*\))")),
    ("CG-JS-EVAL-001", re.compile(r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(")),
    ("CG-JS-EVAL-001", re.compile(r"\bset(Timeout|Interval)\s*\(\s*[\"'`]")),
    ("CG-JS-STORAGE-001", re.compile(r"(localStorage|sessionStorage)\.setItem\s*\(\s*[\"'`][^\"'`]*(token|jwt|password|secret|session)[^\"'`]*[\"'`]", re.I)),
    ("CG-JS-TLS-001", re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0")),
    ("CG-JS-CORS-001", re.compile(r"Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*[\"']")),
]
DART_RULES = [
    ("CG-JS-TLS-001", re.compile(r"badCertificateCallback\s*=\s*\([^)]*\)\s*(=>\s*true|\{\s*return\s+true)")),
    ("CG-JS-STORAGE-001", re.compile(r"(SharedPreferences|prefs)\.?\w*\.set(String)\s*\(\s*[\"'][^\"']*(token|password|secret|jwt)", re.I)),
]

SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b")),
    ("OpenAI-style key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]
CONFIG_SECRET_RE = re.compile(
    r"(?i)^\s*[\"']?([\w.-]*(password|passwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|token))[\"']?\s*[:=]\s*"
    r"[\"']?([^\"'\s#]{3,})[\"']?\s*$")
CONFIG_PLACEHOLDER_RE = re.compile(r"(?i)^(\$\{.*\}|\$\w+|<.*>|\{\{.*\}\}|changeme|change_me|x{3,}|\*{3,}|your[-_].*|"
                                   r"example.*|dummy.*|placeholder|redacted|null|none|false|true|env\(.*\)|"
                                   r"!vault.*|secret\(.*\)|\%\(.*\)s)$")
WEAK_DEFAULTS = {"admin", "odoo", "postgres", "password", "123456", "root", "test"}


def analyze_js(path, text, ctx):
    out = []
    if len(text) > 2_000_000 or (text.count("\n") < 5 and len(text) > 20000):   # minified bundle
        return out
    rules = DART_RULES if path.endswith(".dart") else JS_RULES
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith(("//", "*", "/*")):
            continue
        for rid, rx in rules:
            if rx.search(line):
                out.append(make(rid, path, i, line))
                break
    return out


def analyze_secrets(path, text, ctx, structured_config=False):
    out = []
    base = path.rsplit("/", 1)[-1]
    if re.fullmatch(r"\.env(\.[\w-]+)?", base) and not base.endswith((".example", ".sample", ".template", ".dist")):
        out.append(make("CG-SEC-003", path, 1, "", f"{base} is tracked in the repository"))
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        for label, rx in SECRET_PATTERNS:
            if rx.search(line):
                if re.search(r"(?i)example|dummy|fake|sample|xxxx", line):
                    continue
                out.append(make("CG-SEC-001", path, i, line, f"{label} detected"))
                break
        else:
            if structured_config:
                m = CONFIG_SECRET_RE.match(line)
                if m and not CONFIG_PLACEHOLDER_RE.match(m.group(3)) and \
                        (len(m.group(3)) >= 6 or m.group(3).lower() in WEAK_DEFAULTS):
                    weak = m.group(3).lower() in WEAK_DEFAULTS
                    out.append(make("CG-SEC-002", path, i, line,
                                    f"'{m.group(1)}' has a literal value" + (" (weak default)" if weak else ""),
                                    confidence="medium" if weak or len(m.group(3)) >= 12 else None))
    return out


def analyze_dockerfile(path, text, ctx):
    out = []
    has_user = False
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        s = line.strip()
        u = s.upper()
        if u.startswith("USER "):
            has_user = s.split()[1] not in ("root", "0")
        if u.startswith("FROM "):
            img = s.split()[1]
            if img.lower() != "scratch" and not img.startswith("$") and \
                    ("@sha256:" not in img) and (":" not in img.split("/")[-1] or img.endswith(":latest")):
                out.append(make("CG-IAC-DOCKER-003", path, i, line))
        if re.match(r"(?i)^(ENV|ARG)\s+\S*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY)\S*[\s=]+\S+", s):
            out.append(make("CG-IAC-DOCKER-002", path, i, line))
        if re.search(r"(curl|wget)[^|]*\|\s*(ba|z)?sh\b", s):
            out.append(make("CG-IAC-DOCKER-004", path, i, line))
    if lines and not has_user:
        out.append(make("CG-IAC-DOCKER-001", path, 1, lines[0]))
    return out


def analyze_compose(path, text, ctx):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if re.search(r"^\s*privileged:\s*true", line):
            out.append(make("CG-IAC-COMPOSE-001", path, i, line))
        m = re.search(r"[\"']?(\d+\.\d+\.\d+\.\d+:)?(\d+):5432[\"']?", line)
        if m and line.strip().startswith("-") and not (m.group(1) or "").startswith("127."):
            out.append(make("CG-IAC-COMPOSE-002", path, i, line))
    out += analyze_secrets(path, text, ctx, structured_config=True)
    return out


def analyze_gha(path, text, ctx):
    out = []
    if "pull_request_target" in text and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text):
        i = text[:text.find("pull_request_target")].count("\n") + 1
        out.append(make("CG-CI-001", path, i, line_of(text, i)))
    in_run = False
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*(-\s*)?run:\s*", line):
            in_run = True
        elif re.match(r"^\s*(-\s*)?\w[\w-]*:\s", line) and not line.strip().startswith("run"):
            in_run = False
        if in_run and re.search(r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|head_commit|commits)"
                                r"[\w.\[\]*]*\.(title|body|message|name|email|label|ref)|head_ref)", line):
            out.append(make("CG-CI-002", path, i, line))
    return out
