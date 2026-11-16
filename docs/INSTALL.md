# Installation

## Requirements
- Claude Code (skills are loaded from `~/.claude/skills/<name>/SKILL.md`; tested with 2.1.x).
- Python ≥ 3.10, git. PyYAML (usually present; otherwise `python3 -m pip install --user pyyaml`).
- Optional: `jsonschema` for full config validation.

## Global install
```bash
git clone git@github.com:shawkialaddin/compliance-guardian.git
cd compliance-guardian
./install.sh
```
Update later with `git pull && ./install.sh`.
This:
1. copies `compliance-guardian/` to `~/.claude/skills/compliance-guardian/` (an existing install is moved to `*.bak-<timestamp>`);
2. adds a PostToolUse hook (`Write|Edit|MultiEdit` → `cg.py hook`) to `~/.claude/settings.json` (backup kept, idempotent, existing hooks preserved);
3. appends a marked pointer block to `~/.claude/CLAUDE.md` (backup kept, idempotent).

`CLAUDE_CONFIG_DIR` is honoured. Use `--no-hook` / `--no-claude-md` to skip steps, `--link` to symlink for development, `--uninstall` to remove everything (backups kept).

Restart open Claude Code sessions afterwards. Verify with `/compliance-guardian explain CG-ODOO-SUDO-001`.

## Hook behaviour
After each file edit the hook scans **only that file** (local analyzers, <1 s typical) and, if MEDIUM+ candidates exist, gives Claude a short note to verify them. It never blocks the edit. Disable per session with `CG_HOOK_DISABLE=1`, per project with `scan: {post_edit_hook: false}`, or tune with `scan.hook_min_severity`.

## Optional external scanners (never auto-installed)
`python3 ~/.claude/skills/compliance-guardian/scripts/cg.py tools` lists what is installed and how to install the rest, e.g. `pipx install semgrep bandit detect-secrets checkov pip-audit`. Semgrep runs with `--metrics=off` and only the bundled local rules. `pip-audit` and `trivy` contact vulnerability databases (package names only) and run only with `--allow-network`.

## Repository integrations
```bash
CG=~/.claude/skills/compliance-guardian/scripts/cg.py
python3 $CG init . --profile combined-eu-ksa-eg --ci github --pre-commit
python3 $CG vendor .compliance-guardian      # CI uses the vendored copy (pin it by committing)
```
