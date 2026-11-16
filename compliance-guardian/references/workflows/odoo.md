# Workflow: odoo (specialised Odoo checks)

1. Determine version: `.compliance-guardian.yaml project.odoo_version` or manifests (`17.0.x.y.z`). State it; APIs differ (e.g. 18+ `check_access`/`has_access`; 15+ `t-out`, `t-raw` deprecated; 17+ `odoo.tools.SQL`). Verify version-specific claims against that version's source when unsure.
2. `python3 "$CG" scan <addons_path> --min-severity LOW`.
3. Walk `references/odoo-security.md` sections for each module touched: ACL CSV → record rules → groups → models (public methods, sudo, computed/related fields, compute_sudo) → controllers (auth/csrf/type/cors, ownership checks) → views/QWeb/OWL → data files (crons, server actions, mail templates) → manifest/hooks/migrations.
4. For each sudo(): answer — who can reach it? what record set? constrained by what? Justified sudo is not a finding.
5. For each public/none route: what data is returned/modified? Is it intentionally public?
6. Build an access matrix table (group × model × CRUD + rule domain) for models with personal data.
7. Report, then propose fixes that preserve workflows, multi-company and portal behaviour, and upgrade compatibility (no renamed XML ids, no dropped fields without migration).
