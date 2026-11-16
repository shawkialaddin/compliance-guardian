"""Finding model, severity ordering, fingerprinting and redaction."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Optional

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower = worse
CONFIDENCES = ["high", "medium", "low"]

# Verification states for a finding (separate from control statuses).
#   candidate       - produced by a rule; NOT yet contextually verified
#   confirmed       - a reviewer (human or Claude with evidence) verified it is real
#   false_positive  - verified not exploitable / not applicable, with rationale
#   fixed           - remediated and re-scan / regression test verified
VERIFICATION_STATES = ["candidate", "confirmed", "false_positive", "fixed"]

# Control statuses (regulatory matrix)
CONTROL_STATUSES = [
    "PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE", "NOT_TESTED",
    "MANUAL_REVIEW_REQUIRED", "LEGAL_REVIEW_REQUIRED",
]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    path: str
    line: int
    message: str
    snippet: str = ""
    cwe: list = field(default_factory=list)
    owasp: list = field(default_factory=list)
    category: str = "security"          # security | privacy | config | compliance | compat
    remediation: str = ""
    example_fix: str = ""
    tool: str = "compliance-guardian"
    column: int = 0
    context: dict = field(default_factory=dict)
    verification: str = "candidate"
    triage_note: str = ""
    exception_id: Optional[str] = None
    fingerprint: str = ""
    id: str = ""                          # CG-F-xxxx assigned after sorting

    def finalize(self) -> "Finding":
        self.snippet = redact(self.snippet.strip())[:300]
        if not self.fingerprint:
            norm = re.sub(r"\s+", " ", self.snippet).strip()
            raw = f"{self.rule_id}|{self.path}|{norm or self.line}"
            self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return self

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- redaction
_SECRET_KEY_RE = re.compile(
    r"""(?ix)
    ([\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|
     client[_-]?secret|auth[_-]?token|token|admin_passwd|bearer)[\w-]*)
    (\s*["']?\s*[:=]\s*[rbuf]?["'])([^"']{1,})(["'])
    """
)
_SECRET_KEY_BARE_RE = re.compile(
    r"(?i)([\w.-]*(?:passwd|password|pwd|secret|api_?key|apikey|access_?key|token)[\w-]*)(\s*[:=]\s*)(?![\"'$<{(])(?![\w.\[\]]*\()(?!(self|request|os|env|kw|post)\b)([^\s#,;]{3,})"
)
_KNOWN_TOKEN_RES = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"sk_(live|test)_[0-9a-zA-Z]{16,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*", re.M),
]


def redact(text: str) -> str:
    """Remove secret values from a code snippet before it is stored or printed."""
    if not text:
        return text
    out = _SECRET_KEY_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***REDACTED***{m.group(4)}", text)
    out = _SECRET_KEY_BARE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***REDACTED***", out)
    for rx in _KNOWN_TOKEN_RES:
        out = rx.sub("***REDACTED***", out)
    return out


def sort_findings(findings: list) -> list:
    conf_rank = {c: i for i, c in enumerate(CONFIDENCES)}
    findings.sort(key=lambda f: (SEV_RANK.get(f.severity, 9), conf_rank.get(f.confidence, 9), f.path, f.line))
    for i, f in enumerate(findings, 1):
        f.id = f"CG-F-{i:04d}"
    return findings
