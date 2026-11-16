# Detection rules

Generated with `cg.py rules`. Severity/confidence are defaults; context can raise or lower them. OWASP tags use explicit editions (OWASP-2021 / API-2023).

| Rule | Severity | Confidence | CWE | OWASP | Title |
|---|---|---|---|---|---|
| CG-ODOO-SUDO-001 | HIGH | medium | CWE-639, CWE-285 | OWASP-2021:A01, API-2023:API1 | Controller uses sudo() on a record selected by request input without ownership check |
| CG-ODOO-SUDO-002 | MEDIUM | low | CWE-200, CWE-285 | OWASP-2021:A01, API-2023:API3 | Public/unauthenticated route reads records with sudo() |
| CG-ODOO-SUDO-003 | HIGH | medium | CWE-915, CWE-269 | OWASP-2021:A01, API-2023:API3 | Mass assignment: request data passed to sudo().create()/write() |
| CG-ODOO-SUDO-004 | MEDIUM | low | CWE-269, CWE-285 | OWASP-2021:A01, API-2023:API5 | RPC-callable public model method performs privileged operation with sudo() |
| CG-ODOO-AUTH-001 | HIGH | medium | CWE-269, CWE-287 | OWASP-2021:A07, API-2023:API2 | Superuser/session manipulation in request handling |
| CG-ODOO-AUTH-002 | HIGH | low | CWE-306 | OWASP-2021:A07, API-2023:API2 | auth='none' route uses an ORM environment |
| CG-ODOO-CSRF-001 | MEDIUM | low | CWE-352 | OWASP-2021:A01 | HTTP route disables CSRF protection |
| CG-ODOO-CORS-001 | MEDIUM | medium | CWE-942 | OWASP-2021:A05, API-2023:API8 | Route allows any CORS origin |
| CG-ODOO-UPLOAD-001 | MEDIUM | low | CWE-434, CWE-400 | OWASP-2021:A04, API-2023:API4 | File upload handled without type/size validation |
| CG-ODOO-RULE-001 | HIGH | medium | CWE-285, CWE-639 | OWASP-2021:A01, API-2023:API1 | Record rule grants all records to portal/public users |
| CG-ODOO-RULE-002 | LOW | medium | CWE-285 | OWASP-2021:A01 | Legacy multi-company record rule pattern |
| CG-ODOO-GROUP-001 | HIGH | low | CWE-269, CWE-266 | OWASP-2021:A01, API-2023:API5 | Group definition implies administrative privileges |
| CG-ODOO-ACL-001 | HIGH | medium | CWE-732, CWE-285 | OWASP-2021:A01 | Model access granted to all users (no group) with write/create/unlink |
| CG-ODOO-ACL-002 | MEDIUM | low | CWE-732, CWE-200 | OWASP-2021:A01 | Model readable by all users (no group) |
| CG-ODOO-ACL-003 | HIGH | medium | CWE-732, CWE-285 | OWASP-2021:A01, API-2023:API5 | Portal/public group granted write/create/unlink |
| CG-ODOO-ACL-004 | INFO | high |  |  | Model has no access control list entry |
| CG-ODOO-CONF-001 | HIGH | high | CWE-256, CWE-521 | OWASP-2021:A07 | Odoo master password (admin_passwd) stored in plaintext or weak |
| CG-ODOO-CONF-002 | MEDIUM | medium | CWE-200 | OWASP-2021:A05 | Database manager listing enabled (list_db = True) |
| CG-ODOO-CONF-003 | MEDIUM | medium | CWE-489 | OWASP-2021:A05 | Developer mode options in server configuration |
| CG-ODOO-XSS-001 | MEDIUM | medium | CWE-79 | OWASP-2021:A03 | Markup() built from interpolated data |
| CG-ODOO-XSS-002 | MEDIUM | medium | CWE-79 | OWASP-2021:A03 | QWeb t-raw renders unescaped content |
| CG-ODOO-XSS-003 | MEDIUM | medium | CWE-79 | OWASP-2021:A03 | Html field with sanitization disabled |
| CG-ODOO-VIEW-001 | LOW | low | CWE-602 | OWASP-2021:A01 | Sensitive field hidden only in the UI |
| CG-ODOO-COMPAT-001 | INFO | medium |  |  | Deprecated access-check API for the configured Odoo version |
| CG-ODOO-RATE-001 | LOW | low | CWE-307, CWE-799 | OWASP-2021:A07, API-2023:API4 | Public authentication-like route; rate limiting not evident |
| CG-ODOO-INFO-001 | LOW | medium | CWE-209 | OWASP-2021:A05 | Exception details returned to the client |
| CG-ODOO-PRIV-002 | LOW | medium | CWE-359 | OWASP-2021:A01 | Sensitive field tracked in chatter |
| CG-ODOO-MANIFEST-001 | LOW | high |  |  | Module manifest version does not match configured Odoo series |
| CG-ODOO-HOOK-001 | INFO | low | CWE-404 |  | Uninstall/init hook may modify or delete data |
| CG-PY-SQLI-001 | HIGH | medium | CWE-89 | OWASP-2021:A03, API-2023:API8 | SQL built with string formatting |
| CG-PY-CMDI-001 | HIGH | medium | CWE-78 | OWASP-2021:A03 | OS command execution with shell or dynamic command |
| CG-PY-EVAL-001 | HIGH | medium | CWE-95 | OWASP-2021:A03 | Dynamic code evaluation |
| CG-PY-EVAL-002 | MEDIUM | low | CWE-95 | OWASP-2021:A03 | safe_eval on request-derived input |
| CG-PY-DESER-001 | HIGH | medium | CWE-502 | OWASP-2021:A08 | Unsafe deserialization |
| CG-PY-SSRF-001 | HIGH | medium | CWE-918 | OWASP-2021:A10, API-2023:API7 | Outbound request to a URL derived from request input |
| CG-PY-TLS-001 | MEDIUM | high | CWE-295 | OWASP-2021:A02, API-2023:API10 | TLS certificate verification disabled |
| CG-PY-TIMEOUT-001 | LOW | high | CWE-400 | API-2023:API4 | HTTP call without timeout |
| CG-PY-LOG-001 | MEDIUM | low | CWE-532 | OWASP-2021:A09 | Potential sensitive data written to logs |
| CG-PY-SECRET-001 | HIGH | medium | CWE-798 | OWASP-2021:A07 | Hard-coded credential |
| CG-PY-CRYPTO-001 | LOW | low | CWE-327, CWE-328 | OWASP-2021:A02 | Weak hash algorithm |
| CG-PY-CRYPTO-002 | MEDIUM | medium | CWE-338 | OWASP-2021:A02 | Non-cryptographic randomness for security value |
| CG-PY-TIMING-001 | LOW | low | CWE-208 | OWASP-2021:A02 | Secret compared with non-constant-time equality |
| CG-PY-PATH-001 | HIGH | medium | CWE-22 | OWASP-2021:A01 | File path derived from request input |
| CG-PY-DJANGO-001 | MEDIUM | medium | CWE-489, CWE-16 | OWASP-2021:A05 | Django debug/insecure settings |
| CG-PY-CSRF-002 | MEDIUM | low | CWE-352 | OWASP-2021:A01 | CSRF protection disabled on view |
| CG-PY-XSS-001 | MEDIUM | medium | CWE-79 | OWASP-2021:A03 | Output marked safe from dynamic content |
| CG-PY-CORS-001 | HIGH | high | CWE-942 | OWASP-2021:A05, API-2023:API8 | Wildcard CORS with credentials |
| CG-PY-JWT-001 | HIGH | high | CWE-347 | OWASP-2021:A07, API-2023:API2 | JWT signature verification disabled |
| CG-PY-DEBUG-001 | MEDIUM | medium | CWE-489 | OWASP-2021:A05 | Application started in debug mode |
| CG-JS-XSS-001 | MEDIUM | low | CWE-79 | OWASP-2021:A03 | DOM sink receives dynamic HTML |
| CG-JS-XSS-002 | MEDIUM | low | CWE-79 | OWASP-2021:A03 | OWL markup() applied to dynamic value |
| CG-JS-EVAL-001 | HIGH | medium | CWE-95 | OWASP-2021:A03 | Dynamic code evaluation in JavaScript |
| CG-JS-STORAGE-001 | LOW | low | CWE-922 | OWASP-2021:A02 | Credential stored in browser/web storage |
| CG-JS-TLS-001 | HIGH | high | CWE-295 | OWASP-2021:A02 | TLS verification disabled (JS/Dart) |
| CG-JS-CORS-001 | MEDIUM | medium | CWE-942 | OWASP-2021:A05 | Wildcard Access-Control-Allow-Origin |
| CG-SEC-001 | HIGH | high | CWE-798 | OWASP-2021:A07 | Known credential/token format in repository |
| CG-SEC-002 | HIGH | low | CWE-798, CWE-260 | OWASP-2021:A07 | Credential-like value in configuration file |
| CG-SEC-003 | MEDIUM | medium | CWE-538 | OWASP-2021:A05 | Environment file committed |
| CG-IAC-DOCKER-001 | LOW | medium | CWE-250 | OWASP-2021:A05 | Container runs as root (no USER instruction) |
| CG-IAC-DOCKER-002 | HIGH | medium | CWE-798, CWE-538 | OWASP-2021:A05 | Secret baked into image via ENV/ARG |
| CG-IAC-DOCKER-003 | LOW | high | CWE-1104 | OWASP-2021:A06, OWASP-2021:A08 | Unpinned base image |
| CG-IAC-DOCKER-004 | MEDIUM | medium | CWE-494 | OWASP-2021:A08 | Remote script piped to shell during build |
| CG-IAC-COMPOSE-001 | HIGH | high | CWE-250 | OWASP-2021:A05 | Privileged container |
| CG-IAC-COMPOSE-002 | MEDIUM | medium | CWE-668 | OWASP-2021:A05 | Database port published on all interfaces |
| CG-CI-001 | HIGH | medium | CWE-829 | OWASP-2021:A08 | pull_request_target workflow checks out untrusted PR code |
| CG-CI-002 | HIGH | medium | CWE-78 | OWASP-2021:A03 | GitHub Actions expression injection in run step |
| CG-PRIV-001 | MEDIUM | low | CWE-359, CWE-285 | OWASP-2021:A01 | Special-category/sensitive personal data field without group restriction |
| CG-PRIV-003 | MEDIUM | low |  |  | Personal data processed but no retention/erasure mechanism detected |
| CG-PRIV-005 | MEDIUM | low |  |  | Potential cross-border personal data transfer |
| CG-CFG-001 | INFO | high |  |  | No project compliance configuration |
| CG-CFG-002 | LOW | high |  |  | Project compliance configuration invalid |

Semgrep rules (optional, `rules/semgrep/`): js-innerhtml-dynamic js-owl-markup-dynamic js-eval odoo-sudo-browse-request-param odoo-public-route-sudo odoo-sudo-create-write-kwargs odoo-csrf-disabled odoo-sql-string-formatting odoo-superuser-in-request odoo-auth-none-orm odoo-route-file-path odoo-markup-fstring odoo-html-sanitize-false odoo-qweb-t-raw odoo-sensitive-logging odoo-hardcoded-credential odoo-dynamic-eval odoo-unsafe-subprocess py-unsafe-deserialization py-tls-verify-disabled py-jwt-no-verify py-django-mark-safe-dynamic py-cors-wildcard-credentials py-insecure-random-token 
