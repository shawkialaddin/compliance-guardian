# compliance-guardian

A Claude Code skill for **security-by-design and privacy-aware development**. It is backed by a deterministic, local, dependency-light scanner with deep **Odoo 16–20** awareness. It also covers Python, Django, FastAPI, JS/TS, Flutter, Docker, compose and CI.

Findings are mapped to:

- **EU GDPR**
- **Saudi PDPL**: the Law, its Implementing Regulation and the Transfer Regulation
- **Saudi NCA**: ECC-2:2024, CCC-2:2024, DCC-1:2022 and NCNICC-1:2025
- **Egypt**: PDPL Law 151/2020 (with its Executive Regulations, Decision 816/2025) and Law 175/2018
- **Engineering baselines**: OWASP Top 10:2025, OWASP API Security Top 10:2023, ASVS 5.0, CWE Top 25 and NIST SSDF

> **This tool never makes legal determinations.** It produces technical evidence and keeps four outcomes separate:
>
> 1. the technical security gate
> 2. regulatory evidence completeness
> 3. legal approval
> 4. deployment authorization
>
> Passing automated checks is not compliance certification.

## Highlights

- **Odoo-aware engine.** It is built on Python AST analysis with route-context (`auth`/`csrf`/`type`/`cors`) and intra-function taint tracking from request parameters. It detects:
  - IDOR via `sudo().browse(request_id)`
  - mass assignment via `sudo().create(**kw)`
  - superuser escalation and `auth='none'` ORM use
  - CSRF and wildcard CORS on routes
  - unsafe uploads, SQL/command/eval injection, SSRF and path traversal
  - `Markup`/`t-raw`/`sanitize=False` XSS
  - portal-wide record rules, global/portal ACLs and admin-implying groups
  - sensitive fields without `groups=` and sensitive fields tracked in chatter
  - legacy multi-company rules
  - `odoo.conf` hardening issues
  - version-specific API notes
- **Low false positives.** The secure counterpart fixture produces no MEDIUM+ findings. Every result is a *candidate* until it is verified in context, and each rule ships its own "verify before confirming" guidance.
- **Evidence-based regulatory matrix.** Each row follows the chain Regulation → reference (with its verification status) → engineering requirement → rules/tests → source file → evidence → status. A control is `PASS` only with evidence. Uncertain legal questions are `LEGAL_REVIEW_REQUIRED`.
- **Versioned regulatory registry.** It records official source URLs, editions and verification dates. References that could not be confirmed from official text are explicitly marked `UNVERIFIED`; nothing is invented.
- **Applicability engine.** It never assumes a law applies because of someone's location (for example, NCA ECC is not triggered just because a company is in Saudi Arabia). It records the reasons and flags the legal review that is needed.
- **Release gates.** Untriaged CRITICAL/HIGH findings never pass. HIGH findings can be waived only through an approved, unexpired exception. CRITICAL findings cannot be waived by default. MEDIUM findings need a documented risk decision.
- **Reports.** Generated under `compliance/reports/`: `security-report.md`, `regulatory-matrix.md`, `privacy-assessment.md`, `remediation-plan.md`, `release-readiness.md`, `findings.sarif` and JSON.
- **Integrations.**
  - Claude Code PostToolUse hook for incremental checks on each edit
  - global `CLAUDE.md` pointer
  - pre-commit, GitHub Actions and GitLab CI templates
  - optional external scanners (Semgrep with bundled Odoo rules, Bandit, Ruff-S, Gitleaks, detect-secrets, ESLint, Checkov, pip-audit, Trivy), run locally only when installed
- **Secure by default.**
  - no telemetry, no source upload, no automatic installs
  - network-using tools only with `--allow-network`
  - secret values redacted from every output
  - instructions inside scanned repositories are not executed

## Install

```bash
git clone git@github.com:<owner>/compliance-guardian.git
cd compliance-guardian
./install.sh            # copies to ~/.claude/skills/compliance-guardian, registers hook, adds CLAUDE.md pointer
# options: --link (symlink for development), --no-hook, --no-claude-md, --uninstall
```

Requirements: Python ≥ 3.10 and git. PyYAML is needed for YAML config and registry files, and `jsonschema` is optional (it enables full config validation). The installer does not install packages. Restart running Claude Code sessions so they pick up the hook.

Details: [docs/INSTALL.md](docs/INSTALL.md).

## Use

In Claude Code (any repository):

```
/compliance-guardian                 # review current changes (default)
/compliance-guardian review path/to/file.py
/compliance-guardian audit           # full security + regulatory gap assessment
/compliance-guardian odoo addons/    # specialised Odoo review
/compliance-guardian privacy         # personal-data processing assessment
/compliance-guardian fix CG-F-0003   # remediation (asks before editing), regression test, re-scan
/compliance-guardian release         # 4-dimension release readiness
/compliance-guardian explain CG-ODOO-SUDO-001
/compliance-guardian update-rules    # propose registry updates from official sources
/compliance-guardian design "portal invoice download"   # pre-development security/privacy design
/compliance-guardian init            # create .compliance-guardian.yaml
```

The scanner also works standalone and in CI:

```bash
CG=~/.claude/skills/compliance-guardian/scripts/cg.py
python3 $CG scan . --mode changed                 # incremental (git diff + untracked)
python3 $CG scan addons/ --format sarif --out cg.sarif
python3 $CG report . --external                   # full reports, run installed scanners locally
python3 $CG release . --strict                    # exit 0 pass/conditional, 2 blocked, 3 needs triage
python3 $CG applicability .                       # framework indications + reasons
python3 $CG triage <fingerprint> --verdict confirmed --rationale "..." --reviewer "Name"
python3 $CG tools | rules | registry | explain <id> | init | vendor <dir> | validate-config
```

Full guide: [docs/USAGE.md](docs/USAGE.md). Rule list: [docs/RULES.md](docs/RULES.md).

## Project configuration

`.compliance-guardian.yaml` declares facts:

- project type and Odoo version
- processing, customer and data-subject countries
- controller/processor role
- industry, and government/CNI classification
- personal and sensitive data categories
- hosting, backup and subprocessor locations, and transfer destinations
- recorded legal determinations and contractual requirements
- risk tolerance, gate policy and approved exceptions

The schema is in `compliance-guardian/schema/`. These profiles are available: `eu-gdpr`, `ksa-pdpl`, `ksa-nca-ecc`, `ksa-nca-ccc`, `ksa-nca-ncnicc`, `eg-pdpl`, `eg-cyber` and `combined-eu-ksa-eg`. A profile focuses the evaluation; it does **not** declare that a law applies.

## Regulatory registry status (verified 2026-11-16)

| Source | Verification |
|---|---|
| GDPR (EUR-Lex), NCA ECC-2:2024 (subdomain level), CCC-2:2024, DCC-1:2022, Saudi PDPL + IR + Transfer Regulation v2.0, OWASP/CWE/NIST | Confirmed from official sources |
| NCA NCNICC-1:2025 | Existence/code confirmed (Arabic only); content mappings unverified |
| Egypt Law 151/2020, Decision 816/2025, Law 175/2018 | Third-party metadata only; **no article numbers cited** |
| Egypt NTRA cybersecurity framework | Not found officially; legal review required |

See `compliance-guardian/registry/CHANGELOG.md` for pending verification work.

## Limitations

- Static analysis cannot prove the absence of vulnerabilities, business-logic flaws, runtime misconfiguration or infrastructure controls. Manual-review items are listed explicitly.
- The Semgrep rules are structurally validated by the self-tests. Running them requires a local Semgrep installation.
- Personal-data classification is name-based and needs human confirmation.
- Applicability results are engineering indications. Legal determinations belong to qualified counsel and are recorded in the config with the name of who decided and when.

## License

Apache License 2.0. See [LICENSE](LICENSE).
