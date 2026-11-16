"""Analyzers. Each exposes analyze(path, text, ctx) -> list[Finding]."""
from __future__ import annotations

from .. import catalog
from ..model import Finding


def make(rule_id: str, path: str, line: int, snippet: str = "", message: str = "", severity: str = None,
         confidence: str = None, **context) -> Finding:
    r = catalog.get(rule_id)
    return Finding(
        rule_id=rule_id, title=r["title"], severity=severity or r["severity"],
        confidence=confidence or r["confidence"], path=path, line=line,
        message=message or r["title"], snippet=snippet, cwe=list(r["cwe"]), owasp=list(r["owasp"]),
        category=r["category"], remediation=r["remediation"], example_fix=r["example_fix"],
        context={k: v for k, v in context.items() if v is not None},
    )


def line_of(text: str, lineno: int) -> str:
    lines = text.splitlines()
    return lines[lineno - 1] if 0 < lineno <= len(lines) else ""
