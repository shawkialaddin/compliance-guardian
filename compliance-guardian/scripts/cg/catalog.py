"""Rule catalog: single source of truth for rule metadata.

OWASP references use explicit editions: "OWASP-2021:A01" (OWASP Top 10 2021) and
"API-2023:API1" (OWASP API Security Top 10 2023). CWE IDs reference MITRE CWE.

Every rule carries `verify`: the contextual check a reviewer must perform before a
candidate finding may be classified as CONFIRMED. Scanner output is never a
confirmed vulnerability by itself.
"""
from __future__ import annotations

R = {}


def rule(rid, title, severity, confidence, cwe, owasp, category, remediation, verify, example_fix=""):
    R[rid] = dict(id=rid, title=title, severity=severity, confidence=confidence, cwe=cwe,
                  owasp=owasp, category=category, remediation=remediation, verify=verify,
                  example_fix=example_fix)


# ----------------------------------------------------------------- Odoo: access control
rule("CG-ODOO-SUDO-001", "Controller uses sudo() on a record selected by request input without ownership check",
     "HIGH", "medium", ["CWE-639", "CWE-285"], ["OWASP-2021:A01", "API-2023:API1"], "security",
     "Do not combine sudo() with a request-supplied id. Browse as the current user so ACLs and record rules apply, "
     "or verify ownership/access token (e.g. portal `_document_check_access`, `consteq(access_token, ...)`) before "
     "elevating, and elevate only the minimal operation.",
     "Confirm the id/domain value is attacker-controllable, that no earlier check (decorator, helper, record rule on a "
     "non-sudo browse, access_token check) constrains it, and that the returned/modified data is not intended public.",
     "order = request.env['sale.order'].browse(order_id)\n"
     "order.check_access('read')  # Odoo 18+: check_access(); <=17: check_access_rights('read') + check_access_rule('read')\n"
     "# portal: order_sudo = self._document_check_access('sale.order', order_id, access_token=access_token)")
rule("CG-ODOO-SUDO-002", "Public/unauthenticated route reads records with sudo()",
     "MEDIUM", "low", ["CWE-200", "CWE-285"], ["OWASP-2021:A01", "API-2023:API3"], "security",
     "Return only fields intended for anonymous users (explicit field list), restrict the domain to published/public "
     "records, and avoid sudo() where the public user's ACLs suffice.",
     "Check which fields/records are returned. If only explicitly public data (e.g. website_published products) is "
     "exposed, mark false_positive with rationale.",
     "products = request.env['product.template'].sudo().search_read(\n"
     "    [('website_published', '=', True)], ['name', 'list_price'], limit=50)")
rule("CG-ODOO-SUDO-003", "Mass assignment: request data passed to sudo().create()/write()",
     "HIGH", "medium", ["CWE-915", "CWE-269"], ["OWASP-2021:A01", "API-2023:API3"], "security",
     "Whitelist the fields accepted from the request and validate types; never pass the raw kwargs dict to a sudo "
     "create/write (attacker can set user_id, company_id, state, groups_id, etc.).",
     "Confirm the dict reaches create/write unfiltered (no field whitelist in between).",
     "ALLOWED = {'name', 'email', 'phone'}\nvals = {k: v for k, v in kw.items() if k in ALLOWED}\n"
     "request.env['crm.lead'].sudo().create(vals)")
rule("CG-ODOO-SUDO-004", "RPC-callable public model method performs privileged operation with sudo()",
     "MEDIUM", "low", ["CWE-269", "CWE-285"], ["OWASP-2021:A01", "API-2023:API5"], "security",
     "Methods not starting with '_' are callable over JSON-RPC/XML-RPC by any user with model access. Make helper "
     "methods private (leading underscore), or add explicit group/ownership checks before sudo().",
     "Determine whether a low-privileged user (portal user or internal user) can call the method via call_kw and "
     "what the sudo() block lets them read/modify. Button methods referenced in views are expected to be public.",
     "def _sync_partner_data(self):  # private: not reachable via RPC\n    ...")
rule("CG-ODOO-AUTH-001", "Superuser/session manipulation in request handling",
     "HIGH", "medium", ["CWE-269", "CWE-287"], ["OWASP-2021:A07", "API-2023:API2"], "security",
     "Do not switch to SUPERUSER_ID or assign request.session.uid/request.uid manually. Use the authenticated "
     "environment and elevate narrowly with sudo() on specific, validated records.",
     "Check if the code path is reachable without authentication and what the superuser environment can do.",
     "")
rule("CG-ODOO-AUTH-002", "auth='none' route uses an ORM environment",
     "HIGH", "low", ["CWE-306"], ["OWASP-2021:A07", "API-2023:API2"], "security",
     "auth='none' routes run without user/database authentication. Use auth='public' (public user, ACL-bound) or "
     "auth='user', or authenticate the caller explicitly (signed request / token compared with consteq/hmac).",
     "Confirm no explicit authentication (signature/token) is performed before ORM access.", "")
rule("CG-ODOO-CSRF-001", "HTTP route disables CSRF protection",
     "MEDIUM", "low", ["CWE-352"], ["OWASP-2021:A01"], "security",
     "Keep csrf=True for browser-facing type='http' POST routes. For machine-to-machine webhooks, authenticate the "
     "request (HMAC signature with hmac.compare_digest / provider-signed payload) instead of relying on session cookies.",
     "csrf=False is acceptable for webhooks that do not rely on the session cookie and authenticate requests "
     "explicitly, or for GET-only idempotent routes. Confirm a state-changing action is reachable with a victim's session.",
     "@http.route('/hook/payment', type='http', auth='public', methods=['POST'], csrf=False)\n"
     "def hook(self, **kw):\n    sig = request.httprequest.headers.get('X-Signature', '')\n"
     "    expected = hmac.new(secret, request.httprequest.get_data(), hashlib.sha256).hexdigest()\n"
     "    if not hmac.compare_digest(sig, expected):\n        raise Forbidden()")
rule("CG-ODOO-CORS-001", "Route allows any CORS origin",
     "MEDIUM", "medium", ["CWE-942"], ["OWASP-2021:A05", "API-2023:API8"], "security",
     "Restrict cors= to the specific trusted origin(s). Wildcard CORS on routes returning user data enables "
     "cross-origin data reads when combined with credentials/tokens.",
     "Check whether the route returns non-public data or performs state changes.", "cors='https://app.example.com'")
rule("CG-ODOO-UPLOAD-001", "File upload handled without type/size validation",
     "MEDIUM", "low", ["CWE-434", "CWE-400"], ["OWASP-2021:A04", "API-2023:API4"], "security",
     "Validate size (reject above a limit), validate MIME type from content (odoo.tools.mimetypes.guess_mimetype), "
     "restrict extensions, store as ir.attachment (never in a web-served path), and never trust the client filename.",
     "Confirm no validation exists in called helpers and that the stored file can be served back or executed.", "")
rule("CG-ODOO-RULE-001", "Record rule grants all records to portal/public users",
     "HIGH", "medium", ["CWE-285", "CWE-639"], ["OWASP-2021:A01", "API-2023:API1"], "security",
     "Portal/public rules must restrict to the user's own records, e.g. "
     "[('partner_id', 'child_of', [user.commercial_partner_id.id])] or published records.",
     "Confirm the model contains non-public data and the group really is portal/public.", "")
rule("CG-ODOO-RULE-002", "Legacy multi-company record rule pattern",
     "LOW", "medium", ["CWE-285"], ["OWASP-2021:A01"], "security",
     "Since Odoo 13 use [('company_id', 'in', company_ids)] (or ['|', ('company_id', '=', False), ('company_id', 'in', "
     "company_ids)]) so isolation follows the user's allowed/active companies.",
     "Check the target Odoo version and whether the model is multi-company.", "")
rule("CG-ODOO-GROUP-001", "Group definition implies administrative privileges",
     "HIGH", "low", ["CWE-269", "CWE-266"], ["OWASP-2021:A01", "API-2023:API5"], "security",
     "Do not make broad groups (base.group_user/portal/public or module user groups) imply base.group_system or "
     "base.group_erp_manager. Grant admin rights explicitly to named administrators.",
     "Confirm which users receive the group and whether the implied privilege is intended.", "")
rule("CG-ODOO-ACL-001", "Model access granted to all users (no group) with write/create/unlink",
     "HIGH", "medium", ["CWE-732", "CWE-285"], ["OWASP-2021:A01"], "security",
     "An ir.model.access line without group applies to every user including portal users. Assign a specific group.",
     "Confirm record rules do not already restrict the model to safe records for portal users.", "")
rule("CG-ODOO-ACL-002", "Model readable by all users (no group)",
     "MEDIUM", "low", ["CWE-732", "CWE-200"], ["OWASP-2021:A01"], "security",
     "Restrict the access line to the intended group. Global read access lets portal users read every record via RPC "
     "unless a record rule restricts it.",
     "Check for global/portal record rules on this model and whether the data is non-public.", "")
rule("CG-ODOO-ACL-003", "Portal/public group granted write/create/unlink",
     "HIGH", "medium", ["CWE-732", "CWE-285"], ["OWASP-2021:A01", "API-2023:API5"], "security",
     "Prefer controller-mediated writes with validation; if direct access is needed, add strict portal record rules "
     "for every granted operation.",
     "Check the corresponding ir.rule restricts portal/public users to their own records for each operation.", "")
rule("CG-ODOO-ACL-004", "Model has no access control list entry",
     "INFO", "high", [], [], "compat",
     "Add ir.model.access.csv lines. (Deny-by-default holds; this is a functional/consistency issue.)",
     "Informational only.", "")
rule("CG-ODOO-CONF-001", "Odoo master password (admin_passwd) stored in plaintext or weak",
     "HIGH", "high", ["CWE-256", "CWE-521"], ["OWASP-2021:A07"], "config",
     "Set a strong master password via the UI so Odoo stores a pbkdf2 hash, keep odoo.conf out of VCS, and "
     "disable the database manager in production.", "Check if this config file is used in production.", "")
rule("CG-ODOO-CONF-002", "Database manager listing enabled (list_db = True)",
     "MEDIUM", "medium", ["CWE-200"], ["OWASP-2021:A05"], "config",
     "Set list_db = False and block /web/database/* at the reverse proxy in production.",
     "Confirm this is a production configuration.", "")
rule("CG-ODOO-CONF-003", "Developer mode options in server configuration",
     "MEDIUM", "medium", ["CWE-489"], ["OWASP-2021:A05"], "config",
     "Remove dev_mode from production configuration.", "Confirm this is a production configuration.", "")
rule("CG-ODOO-XSS-001", "Markup() built from interpolated data",
     "MEDIUM", "medium", ["CWE-79"], ["OWASP-2021:A03"], "security",
     "Markup marks content as safe. Escape dynamic parts: Markup('<b>%s</b>') % value (markupsafe escapes "
     "interpolated values), or odoo.tools.html_escape / plaintext2html.",
     "Check whether interpolated values can contain user-controlled content.",
     "Markup('<p>%s</p>') % partner.name  # value escaped by markupsafe")
rule("CG-ODOO-XSS-002", "QWeb t-raw renders unescaped content",
     "MEDIUM", "medium", ["CWE-79"], ["OWASP-2021:A03"], "security",
     "Use t-out (Odoo 15+) / t-esc. Wrap only trusted, sanitized HTML in Markup on the server side.",
     "Check whether the rendered value can contain user-controlled HTML.", '<span t-out="record.description"/>')
rule("CG-ODOO-XSS-003", "Html field with sanitization disabled",
     "MEDIUM", "medium", ["CWE-79"], ["OWASP-2021:A03"], "security",
     "Keep sanitize=True (default). If specific tags/attributes are needed, use sanitize_tags/sanitize_attributes "
     "carefully and restrict who can write the field via groups=.",
     "Check who can write the field (portal/public/website forms?).", "")
rule("CG-ODOO-VIEW-001", "Sensitive field hidden only in the UI",
     "LOW", "low", ["CWE-602"], ["OWASP-2021:A01"], "privacy",
     "UI attributes (invisible/column_invisible) are not authorization. Add groups= on the field definition "
     "(Python) or restrict via ACL/record rules.", "Check the Python field definition for groups=.", "")
rule("CG-ODOO-COMPAT-001", "Deprecated access-check API for the configured Odoo version",
     "INFO", "medium", [], [], "compat",
     "In Odoo 18+, check_access_rights()/check_access_rule() are superseded by check_access(operation) / "
     "has_access(operation). Verify against the exact Odoo version source before changing.",
     "Informational; confirm the configured Odoo version.", "")
rule("CG-ODOO-RATE-001", "Public authentication-like route; rate limiting not evident",
     "LOW", "low", ["CWE-307", "CWE-799"], ["OWASP-2021:A07", "API-2023:API4"], "security",
     "Ensure throttling exists (reverse proxy limit_req, fail2ban, or application-level counters) for login, OTP, "
     "password reset, signup, and token verification endpoints.",
     "Check reverse proxy / infrastructure configuration; static analysis cannot prove absence.", "")
rule("CG-ODOO-INFO-001", "Exception details returned to the client",
     "LOW", "medium", ["CWE-209"], ["OWASP-2021:A05"], "security",
     "Log the exception server-side (without personal data) and return a generic error message.",
     "Check whether the response reaches unauthenticated clients.", "")
rule("CG-ODOO-PRIV-002", "Sensitive field tracked in chatter",
     "LOW", "medium", ["CWE-359"], ["OWASP-2021:A01"], "privacy",
     "tracking=True copies old/new values into mail.tracking.value visible to record followers. Disable tracking "
     "for sensitive personal data or restrict the field with groups=.", "Confirm the field contains personal data.", "")
rule("CG-ODOO-MANIFEST-001", "Module manifest version does not match configured Odoo series",
     "LOW", "high", [], [], "compat",
     "Use version '<odoo_series>.x.y.z' (e.g. '17.0.1.0.0') consistent with the target series.", "", "")
rule("CG-ODOO-HOOK-001", "Uninstall/init hook may modify or delete data",
     "INFO", "low", ["CWE-404"], [], "privacy",
     "Review hook for irreversible deletion of business/personal data and retention obligations.", "Manual review.", "")

# ----------------------------------------------------------------- Generic Python
rule("CG-PY-SQLI-001", "SQL built with string formatting",
     "HIGH", "medium", ["CWE-89"], ["OWASP-2021:A03", "API-2023:API8"], "security",
     "Pass values as query parameters: cr.execute('... WHERE id = %s', (value,)). For identifiers use "
     "psycopg2.sql.Identifier or odoo.tools.SQL (Odoo 17+). Prefer the ORM.",
     "Confirm at least one interpolated value is not a hard-coded constant / model _table name.",
     "self.env.cr.execute('SELECT id FROM res_partner WHERE email = %s', (email,))")
rule("CG-PY-CMDI-001", "OS command execution with shell or dynamic command",
     "HIGH", "medium", ["CWE-78"], ["OWASP-2021:A03"], "security",
     "Use subprocess.run([...], shell=False) with an argument list; validate arguments against an allow-list.",
     "Confirm the command contains externally influenced data.", "subprocess.run(['pg_dump', '--', dbname], check=True)")
rule("CG-PY-EVAL-001", "Dynamic code evaluation",
     "HIGH", "medium", ["CWE-95"], ["OWASP-2021:A03"], "security",
     "Do not eval/exec untrusted data. Use ast.literal_eval for literals, json for data, or odoo.tools.safe_eval "
     "only on administrator-controlled expressions.",
     "Confirm the evaluated string can be influenced by a non-administrator.", "value = ast.literal_eval(raw)")
rule("CG-PY-EVAL-002", "safe_eval on request-derived input",
     "MEDIUM", "low", ["CWE-95"], ["OWASP-2021:A03"], "security",
     "Never feed request data to safe_eval; parse domains/values with explicit validation.",
     "Confirm request data reaches safe_eval.", "")
rule("CG-PY-DESER-001", "Unsafe deserialization",
     "HIGH", "medium", ["CWE-502"], ["OWASP-2021:A08"], "security",
     "Use json, or yaml.safe_load. Never unpickle data that crosses a trust boundary.",
     "Confirm the serialized data can come from an untrusted source.", "data = yaml.safe_load(stream)")
rule("CG-PY-SSRF-001", "Outbound request to a URL derived from request input",
     "HIGH", "medium", ["CWE-918"], ["OWASP-2021:A10", "API-2023:API7"], "security",
     "Allow-list destination hosts/schemes, resolve and block private/link-local ranges, disable redirects or "
     "re-validate them.", "Confirm the URL (or host part) is attacker-controllable.", "")
rule("CG-PY-TLS-001", "TLS certificate verification disabled",
     "MEDIUM", "high", ["CWE-295"], ["OWASP-2021:A02", "API-2023:API10"], "security",
     "Remove verify=False; configure the CA bundle if a private CA is used.", "Confirm this runs outside tests.", "")
rule("CG-PY-TIMEOUT-001", "HTTP call without timeout",
     "LOW", "high", ["CWE-400"], ["API-2023:API4"], "security",
     "Always pass timeout= to outbound HTTP calls (a hung call can block Odoo workers/crons).", "", "requests.get(url, timeout=10)")
rule("CG-PY-LOG-001", "Potential sensitive data written to logs",
     "MEDIUM", "low", ["CWE-532"], ["OWASP-2021:A09"], "privacy",
     "Do not log credentials, tokens or personal identifiers. Log record ids or masked values.",
     "Confirm the logged value actually contains secrets/personal data.", "_logger.info('Login failed for user id %s', user.id)")
rule("CG-PY-SECRET-001", "Hard-coded credential",
     "HIGH", "medium", ["CWE-798"], ["OWASP-2021:A07"], "security",
     "Load secrets from environment / secret manager / ir.config_parameter restricted to admins; rotate the exposed "
     "secret. Never commit real credentials.", "Confirm it is a real credential, not a placeholder or test value.",
     "api_key = os.environ['PAYMENT_API_KEY']")
rule("CG-PY-CRYPTO-001", "Weak hash algorithm",
     "LOW", "low", ["CWE-327", "CWE-328"], ["OWASP-2021:A02"], "security",
     "Use SHA-256+ for integrity, and passlib/argon2/bcrypt/pbkdf2 for passwords. MD5/SHA1 are acceptable only for "
     "non-security purposes (pass usedforsecurity=False).", "Check whether the hash protects security-relevant data.", "")
rule("CG-PY-CRYPTO-002", "Non-cryptographic randomness for security value",
     "MEDIUM", "medium", ["CWE-338"], ["OWASP-2021:A02"], "security",
     "Use the secrets module (secrets.token_urlsafe) for tokens, OTPs, passwords and nonces.",
     "Confirm the value is security-relevant.", "token = secrets.token_urlsafe(32)")
rule("CG-PY-TIMING-001", "Secret compared with non-constant-time equality",
     "LOW", "low", ["CWE-208"], ["OWASP-2021:A02"], "security",
     "Use hmac.compare_digest (or odoo.tools.consteq) for tokens, signatures and API keys.",
     "Confirm both operands are secrets/tokens.", "if not hmac.compare_digest(token, expected): raise Forbidden()")
rule("CG-PY-PATH-001", "File path derived from request input",
     "HIGH", "medium", ["CWE-22"], ["OWASP-2021:A01"], "security",
     "Never build filesystem paths from request data; use attachment ids with access checks or validate against a "
     "base directory with os.path.realpath + commonpath.", "Confirm the path value is attacker-controllable.", "")
rule("CG-PY-DJANGO-001", "Django debug/insecure settings",
     "MEDIUM", "medium", ["CWE-489", "CWE-16"], ["OWASP-2021:A05"], "config",
     "DEBUG=False and explicit ALLOWED_HOSTS in production settings; load SECRET_KEY from environment.",
     "Confirm this is a production settings module.", "")
rule("CG-PY-CSRF-002", "CSRF protection disabled on view",
     "MEDIUM", "low", ["CWE-352"], ["OWASP-2021:A01"], "security",
     "Remove @csrf_exempt for session-authenticated views; authenticate webhooks by signature.",
     "Confirm the view is cookie-session authenticated and state changing.", "")
rule("CG-PY-XSS-001", "Output marked safe from dynamic content",
     "MEDIUM", "medium", ["CWE-79"], ["OWASP-2021:A03"], "security",
     "Use format_html / escape() instead of mark_safe on interpolated values.", "Check the data origin.", "")
rule("CG-PY-CORS-001", "Wildcard CORS with credentials",
     "HIGH", "high", ["CWE-942"], ["OWASP-2021:A05", "API-2023:API8"], "security",
     "List allowed origins explicitly when allow_credentials=True.", "", "")
rule("CG-PY-JWT-001", "JWT signature verification disabled",
     "HIGH", "high", ["CWE-347"], ["OWASP-2021:A07", "API-2023:API2"], "security",
     "Always verify signatures and pin algorithms: jwt.decode(token, key, algorithms=['RS256']).", "", "")
rule("CG-PY-DEBUG-001", "Application started in debug mode",
     "MEDIUM", "medium", ["CWE-489"], ["OWASP-2021:A05"], "config",
     "Disable debug in production; drive via environment variable.", "Confirm not a dev-only entrypoint.", "")

# ----------------------------------------------------------------- JS / TS / Dart
rule("CG-JS-XSS-001", "DOM sink receives dynamic HTML",
     "MEDIUM", "low", ["CWE-79"], ["OWASP-2021:A03"], "security",
     "Use textContent / framework templating (OWL t-esc/t-out, React JSX) or sanitize with DOMPurify.",
     "Confirm the assigned value can contain user-controlled data.", "el.textContent = value;")
rule("CG-JS-XSS-002", "OWL markup() applied to dynamic value",
     "MEDIUM", "low", ["CWE-79"], ["OWASP-2021:A03"], "security",
     "markup() disables escaping. Only wrap server-sanitized HTML.", "Check value provenance.", "")
rule("CG-JS-EVAL-001", "Dynamic code evaluation in JavaScript",
     "HIGH", "medium", ["CWE-95"], ["OWASP-2021:A03"], "security",
     "Remove eval/new Function; use JSON.parse or explicit dispatch tables.", "Confirm dynamic input reaches it.", "")
rule("CG-JS-STORAGE-001", "Credential stored in browser/web storage",
     "LOW", "low", ["CWE-922"], ["OWASP-2021:A02"], "security",
     "Prefer HttpOnly, Secure, SameSite cookies or in-memory tokens; for Flutter use flutter_secure_storage.",
     "Confirm a credential/token is stored.", "")
rule("CG-JS-TLS-001", "TLS verification disabled (JS/Dart)",
     "HIGH", "high", ["CWE-295"], ["OWASP-2021:A02"], "security",
     "Do not disable certificate validation; pin or trust a specific CA instead.", "Confirm not test-only.", "")
rule("CG-JS-CORS-001", "Wildcard Access-Control-Allow-Origin",
     "MEDIUM", "medium", ["CWE-942"], ["OWASP-2021:A05"], "security",
     "Allow specific origins.", "Check the endpoint data sensitivity.", "")

# ----------------------------------------------------------------- Secrets / infra / CI
rule("CG-SEC-001", "Known credential/token format in repository",
     "HIGH", "high", ["CWE-798"], ["OWASP-2021:A07"], "security",
     "Revoke and rotate the credential, remove it from history (git filter-repo), and load it from a secret store.",
     "Confirm it is not a documented fake/example key.", "")
rule("CG-SEC-002", "Credential-like value in configuration file",
     "HIGH", "low", ["CWE-798", "CWE-260"], ["OWASP-2021:A07"], "security",
     "Use environment variables / secret manager references; keep real config out of VCS.",
     "Confirm it is a real secret, not a placeholder/dev default.", "")
rule("CG-SEC-003", "Environment file committed",
     "MEDIUM", "medium", ["CWE-538"], ["OWASP-2021:A05"], "security",
     "Add .env to .gitignore; commit a .env.example with placeholders only.", "Check contents for real secrets.", "")
rule("CG-IAC-DOCKER-001", "Container runs as root (no USER instruction)",
     "LOW", "medium", ["CWE-250"], ["OWASP-2021:A05"], "config",
     "Add a non-root USER (the official odoo image already uses 'odoo').", "Check base image default user.", "")
rule("CG-IAC-DOCKER-002", "Secret baked into image via ENV/ARG",
     "HIGH", "medium", ["CWE-798", "CWE-538"], ["OWASP-2021:A05"], "security",
     "Inject secrets at runtime (docker secrets, env from orchestrator), never in image layers.", "", "")
rule("CG-IAC-DOCKER-003", "Unpinned base image",
     "LOW", "high", ["CWE-1104"], ["OWASP-2021:A06", "OWASP-2021:A08"], "config",
     "Pin base images by version and ideally digest.", "", "FROM odoo:17.0@sha256:<digest>")
rule("CG-IAC-DOCKER-004", "Remote script piped to shell during build",
     "MEDIUM", "medium", ["CWE-494"], ["OWASP-2021:A08"], "security",
     "Download, verify checksum/signature, then execute.", "", "")
rule("CG-IAC-COMPOSE-001", "Privileged container",
     "HIGH", "high", ["CWE-250"], ["OWASP-2021:A05"], "config", "Remove privileged: true; grant specific capabilities.", "", "")
rule("CG-IAC-COMPOSE-002", "Database port published on all interfaces",
     "MEDIUM", "medium", ["CWE-668"], ["OWASP-2021:A05"], "config",
     "Do not publish PostgreSQL; or bind to 127.0.0.1:5432:5432.", "Confirm deployment exposure (firewall).", "")
rule("CG-CI-001", "pull_request_target workflow checks out untrusted PR code",
     "HIGH", "medium", ["CWE-829"], ["OWASP-2021:A08"], "security",
     "Use pull_request for untrusted code, or never execute checked-out PR code with secrets in scope.", "", "")
rule("CG-CI-002", "GitHub Actions expression injection in run step",
     "HIGH", "medium", ["CWE-78"], ["OWASP-2021:A03"], "security",
     "Pass untrusted event fields via env: and reference them as \"$VAR\".", "", "")

# ----------------------------------------------------------------- Privacy / compliance (project-level)
rule("CG-PRIV-001", "Special-category/sensitive personal data field without group restriction",
     "MEDIUM", "low", ["CWE-359", "CWE-285"], ["OWASP-2021:A01"], "privacy",
     "Restrict the field with groups= (Odoo) / field-level permissions, minimise collection, and document the "
     "lawful basis/condition for processing this category.",
     "Confirm the field really holds the classified category and that model access is broad.", "")
rule("CG-PRIV-003", "Personal data processed but no retention/erasure mechanism detected",
     "MEDIUM", "low", [], [], "privacy",
     "Define retention periods per data category, implement scheduled anonymization/deletion respecting legal "
     "retention (accounting/tax records), and document exceptions.",
     "Manual: retention may be handled outside this codebase; record evidence.", "")
rule("CG-PRIV-005", "Potential cross-border personal data transfer",
     "MEDIUM", "low", [], [], "compliance",
     "Document the transfer mechanism required by each applicable law; this requires legal review.",
     "LEGAL_REVIEW_REQUIRED: determine whether a transfer occurs and which mechanism applies.", "")
rule("CG-CFG-001", "No project compliance configuration",
     "INFO", "high", [], [], "compliance",
     "Create .compliance-guardian.yaml (cg.py init) so applicability can be determined. Only baseline security "
     "checks were applied; regulatory applicability is unresolved.", "", "")
rule("CG-CFG-002", "Project compliance configuration invalid",
     "LOW", "high", [], [], "compliance", "Fix the configuration according to schema/compliance-guardian.schema.json.", "", "")

# External tool pass-through rules are created dynamically as EXT-<tool>-<id>.


def get(rid: str) -> dict:
    return R.get(rid) or dict(id=rid, title=rid, severity="MEDIUM", confidence="low", cwe=[], owasp=[],
                              category="security", remediation="", verify="", example_fix="")
