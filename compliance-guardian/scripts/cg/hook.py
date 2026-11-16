"""Claude Code PostToolUse hook: incremental single-file check after Write/Edit/MultiEdit.

Fast (one file, local analyzers only), never blocks, never fails the tool call. Emits
`additionalContext` so Claude sees candidate findings and verifies them in context.
Disable globally with CG_HOOK_DISABLE=1, or per project with `scan: {post_edit_hook: false}`.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

RELEVANT = (".py", ".xml", ".csv", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".dart", ".conf", ".cfg",
            ".yml", ".yaml", ".env", ".json", ".toml", ".ini")


def main() -> int:
    try:
        if os.environ.get("CG_HOOK_DISABLE", "").lower() in ("1", "true", "yes"):
            return 0
        payload = json.load(sys.stdin)
        ti = payload.get("tool_input") or {}
        fp = ti.get("file_path") or ti.get("notebook_path")
        if not fp:
            return 0
        p = Path(fp)
        name = p.name.lower()
        if not p.is_file() or not (name.endswith(RELEVANT) or name.startswith(("dockerfile", ".env"))):
            return 0
        if p.stat().st_size > 1_000_000:
            return 0
        from .config import find_project_root, load_config
        from .model import SEV_RANK
        from .scanner import analyze_file, apply_triage_and_exceptions
        from .config import load_optional, odoo_version
        root = find_project_root(p.parent)
        cfg, _ = load_config(root)
        scan_cfg = (cfg or {}).get("scan") or {}
        if scan_cfg.get("post_edit_hook") is False:
            return 0
        threshold = SEV_RANK.get(str(scan_cfg.get("hook_min_severity", "MEDIUM")).upper(), 2)
        try:
            rel = p.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = p.as_posix()
        ctx = {"odoo_version": odoo_version(cfg)}
        findings = analyze_file(p, rel, ctx, [], set())
        for f in findings:
            f.finalize()
        apply_triage_and_exceptions(findings, cfg, load_optional(root, "compliance/triage.yaml"))
        findings = [f for f in findings if SEV_RANK.get(f.severity, 4) <= threshold and
                    f.verification not in ("false_positive", "fixed") and not f.exception_id]
        if not findings:
            return 0
        findings.sort(key=lambda f: (SEV_RANK.get(f.severity, 4), f.line))
        lines = [f"compliance-guardian incremental check of {rel}: {len(findings)} candidate finding(s). "
                 "These are rule matches, not confirmed vulnerabilities: verify each in context (see "
                 "`cg.py explain <rule>`), fix real issues with the smallest safe change, and tell the user. "
                 "Do not silently change business permissions."]
        for f in findings[:8]:
            lines.append(f"- [{f.severity}/{f.confidence}] {f.rule_id} line {f.line}: {f.message} | fix: {f.remediation[:180]}")
        if len(findings) > 8:
            lines.append(f"- ... {len(findings) - 8} more (run /compliance-guardian review {rel})")
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                 "additionalContext": "\n".join(lines)}}))
        return 0
    except Exception:  # noqa: BLE001 - a hook must never break the edit loop
        return 0
