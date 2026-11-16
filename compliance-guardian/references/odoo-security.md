# Odoo security review guide (16.0 – 20.0)

Verify version-specific behaviour against the target version's source (`odoo/models.py`, `odoo/http.py`) when in doubt.

## Access control model
- **ir.model.access.csv**: deny by default. A line with empty `group_id` applies to *all* users incl. portal (and public where reachable). Portal/public write/create/unlink is exceptional and needs matching record rules.
- **ir.rule**: global rules (no groups) are intersected (restrict everyone); group rules are unioned among a user's groups. `[(1,'=',1)]` on a portal/public group grants all records. Multi-company since 13: `[('company_id', 'in', company_ids)]` (+ `('company_id','=',False)` when shared).
- **res.groups**: `implied_ids` propagates; never make broad groups imply `base.group_system`/`group_erp_manager`.
- **sudo()** bypasses ACLs and record rules (and with `sudo()` in 13+ does not change the user, only su mode). Justified uses: reading config params, posting chatter, portal reads *after* `_document_check_access`/access token validation, system crons. Unjustified: sudo on ids/domains from requests without ownership checks, sudo writes with request dicts.
- **with_user()** changes the user (ACLs apply to that user); `with_user(SUPERUSER_ID)` in request paths is privilege escalation. **with_company()** changes company context — ensure the user is allowed in that company (`env.companies`).
- Access checks: ≤17 `check_access_rights(op)` + `check_access_rule(op)`; 18+ `check_access(op)`, `has_access(op)`, `_filtered_access(op)` (older names deprecated). Search/read via ORM without sudo applies rules automatically.
- **Public methods** (no leading `_`) are callable via `/web/dataset/call_kw` by any user with model access — including portal users if they have an ACL line. Treat them as API endpoints.
- **Computed/related fields**: `related` fields are computed as superuser by default (`compute_sudo=True`); a related field can expose data from records the user cannot read — add `groups=`. Stored computed fields with `compute_sudo` likewise.
- **TransientModel** (wizards) need ACLs since 14; wizard actions often run privileged code — check who can open them.
- **Crons / server actions / automations**: run as the configured user (often admin); ensure their inputs (e.g. records created by portal users) cannot steer privileged operations; `safe_eval` contexts must not receive user input.

## Controllers
- `auth='user'` logged-in users (incl. portal); `auth='public'` public user or logged user; `auth='none'` no user/db guarantees — ORM use there is suspect unless request is authenticated another way.
- `type='http'` POST routes are CSRF-protected by default; `csrf=False` is acceptable for signature-verified webhooks. `type='json'` (JSON-RPC) relies on the JSON content type — evaluate CORS/`cors=` before calling it safe.
- Check: object ownership (IDOR), field whitelists (mass assignment), outbound URLs (SSRF), file paths, uploads (size/MIME/extension, storage as ir.attachment), error leakage, rate limiting on login/OTP/reset/signup (often at reverse proxy).
- Website forms: `website_form` model whitelist (`website_form_access`, `_get_form_writable_fields`) — verify exposed fields.

## SQL and data
- Always parameterise: `cr.execute(query, params)`; identifiers via `psycopg2.sql` or `odoo.tools.SQL` (17+). `self._table` interpolation is conventional.
- Attachments: `ir.attachment` access follows the linked record (`res_model`/`res_id`); `public=True` attachments are world-readable; check `access_token` exposure.
- Exports (`/web/export`), reports (`report_action`) and mail templates can leak fields — use `groups=`.
- Retention/deletion: accounting moves and posted documents usually cannot be deleted (legal retention); prefer anonymisation of partner personal fields with documented exceptions.

## Views, QWeb, OWL
- `t-out`/`t-esc` escape; `t-raw` (deprecated 15+) does not. `Markup(...)`/OWL `markup()` mark content safe — only for sanitised HTML.
- `fields.Html(sanitize=False)` stores raw HTML — restrict writers.
- `invisible`/`column_invisible`/`readonly` are UI only — enforce with `groups=` and ACL/rules server-side.
- Portal templates: never render internal-only fields; check `t-att-href` for `javascript:` URLs from user data.

## Lifecycle
- `__manifest__.py`: version series matches target; `external_dependencies` feed SCA; `data` order (security before views).
- Hooks (`pre_init_hook`, `post_init_hook`, `uninstall_hook`) and `migrations/` scripts: raw SQL, data deletion, permission changes — review for irreversibility and retention.
- Config params (`ir.config_parameter`) holding secrets must be restricted to `base.group_system`.
- Server config: `admin_passwd` hashed (set via UI), `list_db = False` in production, `proxy_mode` behind a proxy, no `dev_mode`.
