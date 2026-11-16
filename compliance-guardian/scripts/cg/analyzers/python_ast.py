"""Python AST analyzer: Odoo-aware (controllers, models, ORM) + generic Python/Django/FastAPI.

Design goals:
  * Context-sensitive: route decorators (auth/csrf/type/cors) and lightweight intra-function
    taint tracking from request parameters reduce false positives.
  * Every result is a *candidate*; contextual verification guidance lives in catalog.verify.
"""
from __future__ import annotations

import ast
import re

from . import line_of, make

SQL_RECEIVER_RE = re.compile(r"(^|\.)(_?cr|cursor|_cursor)(\(\))?$")
LOGGER_RE = re.compile(r"(^|\.)(_?logger|logging|_?log|LOGGER|_LOGGER)$")
LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
SENSITIVE_LOG_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api_?key|apikey|authorization|auth_header|credit_?card|card_?number|"
    r"cvv|iban|national_?id|iqama|passport|ssn|otp|private_?key|session_?id|cookie)")
SECRET_NAME_RE = re.compile(
    r"(?i)(^|_)(password|passwd|pwd|secret|secret_?key|api_?key|apikey|access_?key|private_?key|client_?secret|"
    r"auth_?token|access_?token|refresh_?token|bearer_?token|token|admin_passwd)$")
PLACEHOLDER_RE = re.compile(
    r"(?i)^(|x+|\*+|\.+|changeme|change_me|<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s|your[-_ ].*|example.*|dummy.*|"
    r"fake.*|test.*|none|null|false|true|password|secret|redacted|placeholder|todo|tbd)$")
SECURITY_VALUE_RE = re.compile(r"(?i)(token|otp|password|passwd|secret|nonce|salt|pin|api_?key|signature|reset|code)")
ACCESS_CHECK_TOKENS = (
    "_document_check_access", "check_access", "check_access_rule", "check_access_rights", "has_access",
    "_check_access", "consteq", "compare_digest", "_filtered_access", "_get_page_view_values",
)
SIGNATURE_TOKENS = ("compare_digest", "consteq", "hmac", "signature", "verify_signature", "_verify", "jwt.decode")
UPLOAD_VALIDATION_TOKENS = ("mimetype", "guess_mimetype", "content_type", "content_length", "max_size",
                            "MAX_", "allowed_ext", "splitext", "file_size", "len(data", "len(content")
RATE_TOKENS = ("rate", "throttl", "limit_req", "attempt", "captcha", "recaptcha", "turnstile", "cooldown")
REQUEST_SOURCES = ("request.params", "request.httprequest", "request.get_json_data", "request.jsonrequest",
                   "request.get_http_params", "request.dispatcher.jsonrequest")
ORM_OVERRIDES = {"create", "write", "unlink", "copy", "read", "search", "name_get", "default_get", "name_search",
                 "fields_get", "search_read", "read_group", "web_search_read", "web_read", "onchange",
                 "toggle_active", "action_archive", "action_unarchive", "get_views", "init", "_auto_init"}
HTTP_LIB_RE = re.compile(r"^(requests|httpx|urllib\.request|urllib3|session|self\.session|_session)\."
                         r"(get|post|put|patch|delete|head|request|urlopen)$")
PATH_SINKS = {"open", "io.open", "os.open", "os.remove", "os.unlink", "shutil.copy", "shutil.copyfile", "shutil.move",
              "shutil.rmtree", "send_file", "http.send_file", "Stream.from_path", "file_open", "tools.file_open",
              "odoo.tools.file_open", "os.path.join", "pathlib.Path", "Path", "send_from_directory"}


def dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return f"{dotted(node.func)}()"
    if isinstance(node, ast.Subscript):
        return f"{dotted(node.value)}[]"
    return "?"


def is_const(node) -> bool:
    return isinstance(node, ast.Constant)


def kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def const_val(node, default=None):
    return node.value if isinstance(node, ast.Constant) else default


def _is_sql_composer(node) -> bool:
    return isinstance(node, ast.Call) and dotted(node.func).split(".")[-1] in ("SQL", "Composed", "Identifier")


def dynamic_format(node):
    """Return list of interpolated nodes if `node` builds a string dynamically, else None."""
    if isinstance(node, ast.JoinedStr):
        vals = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
        return vals or None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            r = node.right
            vals = list(r.elts) if isinstance(r, ast.Tuple) else [r]
            vals = [v for v in vals if not is_const(v)]
            return vals or None
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parts, stack = [], [node]
        while stack:
            n = stack.pop()
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                stack += [n.left, n.right]
            else:
                parts.append(n)
        if any(isinstance(p, ast.Constant) and isinstance(p.value, str) for p in parts):
            vals = [p for p in parts if not is_const(p)]
            return vals or None
        return None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        if _is_sql_composer(node.func.value):
            return None
        if isinstance(node.func.value, ast.Constant):
            vals = [a for a in node.args if not is_const(a)] + [k.value for k in node.keywords if not is_const(k.value)]
            return vals or None
    return None


def safe_interp(node) -> bool:
    """Interpolations that are conventionally safe identifiers/placeholders (still reported at LOW)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Attribute) and node.attr in ("_table", "_name", "_order", "_parent_name"):
        return True
    if isinstance(node, ast.Name) and node.id.isupper():
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join":
        # ','.join(['%s'] * len(ids)) placeholder expansion
        consts = [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        names = [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]
        return bool(consts) and all(c in ("%s", ",", ", ", "(%s)", "%s,") for c in consts) and \
            all(n in ("len", "range") or n.endswith("ids") for n in names)
    return False


def identifiers(node):
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            yield n.id
        elif isinstance(n, ast.Attribute):
            yield n.attr
        elif isinstance(n, ast.keyword) and n.arg:
            yield n.arg


class RouteInfo:
    def __init__(self, call: ast.Call | None):
        self.auth = "user"
        self.type = "http"
        self.csrf = True
        self.methods = None
        self.cors = None
        self.paths = []
        if call is None:
            return
        if call.args:
            a = call.args[0]
            if isinstance(a, ast.Constant):
                self.paths = [a.value]
            elif isinstance(a, (ast.List, ast.Tuple)):
                self.paths = [e.value for e in a.elts if isinstance(e, ast.Constant)]
        for k in call.keywords:
            v = const_val(k.value)
            if k.arg == "auth" and v:
                self.auth = v
            elif k.arg == "type" and v:
                self.type = v
            elif k.arg == "csrf" and isinstance(k.value, ast.Constant):
                self.csrf = bool(v)
            elif k.arg == "cors":
                self.cors = v
            elif k.arg == "methods" and isinstance(k.value, (ast.List, ast.Tuple)):
                self.methods = [str(const_val(e, "")).upper() for e in k.value.elts]
            elif k.arg == "route" and isinstance(k.value, (ast.List, ast.Tuple, ast.Constant)):
                pass

    @property
    def public(self):
        return self.auth in ("public", "none")

    @property
    def is_json(self):
        return self.type in ("json", "jsonrpc")


class Analyzer(ast.NodeVisitor):
    def __init__(self, path, text, ctx):
        self.path, self.text, self.ctx = path, text, ctx or {}
        self.findings, self.seen = [], set()
        self.func_stack = []          # (FunctionDef, RouteInfo|None, state dict)
        self.class_stack = []
        local = path[len(self.ctx.get("scope_prefix", "")):] if path.startswith(self.ctx.get("scope_prefix", "\0")) else path
        self.is_test = bool(re.search(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$", local))
        self.is_settings = bool(re.search(r"(^|/)settings[^/]*\.py$", path))
        self.odoo_version = self.ctx.get("odoo_version")

    # ------------------------------------------------------------------ helpers
    def add(self, rule_id, node, message="", severity=None, confidence=None, **context):
        line = getattr(node, "lineno", 1)
        key = (rule_id, line)
        if key in self.seen:
            return
        self.seen.add(key)
        if self.is_test and severity not in ("INFO",):
            confidence = "low"
            context["note"] = "located in test code"
        self.findings.append(make(rule_id, self.path, line, line_of(self.text, line), message, severity,
                                  confidence, **context))

    @property
    def fn(self):
        return self.func_stack[-1] if self.func_stack else None

    @property
    def route(self):
        return self.fn[1] if self.fn else None

    def tainted(self, node) -> bool:
        if not self.fn:
            return False
        state = self.fn[2]
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in state["taint"]:
                return True
            if isinstance(n, (ast.Attribute, ast.Call)):
                d = dotted(n)
                if any(d.startswith(s) for s in REQUEST_SOURCES):
                    return True
        return False

    def has_sudo(self, node) -> bool:
        state = self.fn[2] if self.fn else {"sudo_vars": set()}
        n = node
        while True:
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Attribute) and n.func.attr == "sudo":
                    return True
                n = n.func
            elif isinstance(n, ast.Attribute):
                n = n.value
            elif isinstance(n, ast.Subscript):
                n = n.value
            elif isinstance(n, ast.Name):
                return n.id in state["sudo_vars"]
            else:
                return False

    def fn_source(self) -> str:
        if not self.fn:
            return ""
        return ast.get_source_segment(self.text, self.fn[0]) or ""

    # ------------------------------------------------------------------ structure
    def visit_ClassDef(self, node):
        bases = [dotted(b) for b in node.bases]
        is_model = any(b.split(".")[-1] in ("Model", "TransientModel", "AbstractModel") for b in bases)
        self.class_stack.append((node, is_model))
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node):
        route_call = None
        decorators = []
        for d in node.decorator_list:
            name = dotted(d.func if isinstance(d, ast.Call) else d)
            decorators.append(name)
            if name.split(".")[-1] == "route" and isinstance(d, ast.Call):
                route_call = d
            if name.split(".")[-1] == "csrf_exempt":
                self.add("CG-PY-CSRF-002", node)
        route = RouteInfo(route_call) if route_call is not None else None
        state = {"taint": set(), "sudo_vars": set(), "fmt_vars": {}, "exc_vars": set(), "decorators": decorators,
                 "raw": set()}
        if route:
            args = node.args
            for a in args.args + args.kwonlyargs:
                if a.arg not in ("self", "cls"):
                    state["taint"].add(a.arg)
            if args.vararg:
                state["taint"].add(args.vararg.arg)
            if args.kwarg:
                state["taint"].add(args.kwarg.arg)
                state["raw"].add(args.kwarg.arg)
        self.func_stack.append((node, route, state))
        self._prepass(node, state)
        self.generic_visit(node)
        if route:
            self._route_checks(node, route, state)
        elif self.class_stack and self.class_stack[-1][1]:
            self._model_method_checks(node, state)
        self.func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _prepass(self, fn, state):
        """Propagate taint / sudo / format through simple assignments (two passes)."""
        for _ in range(2):
            for n in ast.walk(fn):
                if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                    names = [t.id for t in targets if isinstance(t, ast.Name)]
                    for t in targets:
                        if isinstance(t, ast.Tuple):
                            names += [e.id for e in t.elts if isinstance(e, ast.Name)]
                    if not names:
                        continue
                    if self.tainted(n.value) if self.func_stack else False:
                        state["taint"].update(names)
                    if self.has_sudo(n.value):
                        state["sudo_vars"].update(names)
                    if self._is_raw_dict(n.value, state):
                        state["raw"].update(names)
                    vals = dynamic_format(n.value)
                    if vals:
                        for nm in names:
                            state["fmt_vars"][nm] = vals
                elif isinstance(n, ast.For) and self.tainted(n.iter):
                    if isinstance(n.target, ast.Name):
                        state["taint"].add(n.target.id)
                elif isinstance(n, ast.ExceptHandler) and n.name:
                    state["exc_vars"].add(n.name)

    def _is_raw_dict(self, v, state) -> bool:
        """Request data passed through without a field whitelist."""
        if isinstance(v, ast.Name):
            return v.id in state["raw"]
        if isinstance(v, ast.Call):
            d = dotted(v.func)
            if d == "dict" and v.args and self._is_raw_dict(v.args[0], state):
                return True
            if d.endswith(".copy") and isinstance(v.func, ast.Attribute) and self._is_raw_dict(v.func.value, state):
                return True
            if d in ("json.loads",) and v.args and self.tainted(v.args[0]):
                return True
            if any(d.startswith(s) for s in ("request.get_json_data", "request.httprequest.get_json")):
                return True
        if isinstance(v, (ast.Attribute,)) and dotted(v) in ("request.params", "request.jsonrequest",
                                                             "request.httprequest.form", "request.httprequest.json"):
            return True
        if isinstance(v, ast.Dict):
            return any(k is None and self._is_raw_dict(val, state) for k, val in zip(v.keys, v.values))
        return False

    def visit_Compare(self, node):
        fn = self.fn
        if fn and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            ctxname = fn[0].name
            if fn[1] is not None or re.search(r"(?i)verif|webhook|check|auth|token|sign", ctxname):
                sides = [node.left, node.comparators[0]]
                if not any(isinstance(x, ast.Constant) for x in sides):
                    ids = [i for x in sides for i in identifiers(x)]
                    if any(re.search(r"(?i)token|signature|secret|api_?key|hmac|digest|password|passwd", i) for i in ids) \
                            and not any(i in ("len", "type", "isinstance") for i in ids):
                        self.add("CG-PY-TIMING-001", node)
        self.generic_visit(node)

    # ------------------------------------------------------------------ calls
    def visit_Call(self, node):
        name = dotted(node.func)
        last = name.split(".")[-1]
        route = self.route
        tainted_args = any(self.tainted(a) for a in list(node.args) + [k.value for k in node.keywords])

        # --- SQL injection
        if isinstance(node.func, ast.Attribute) and last in ("execute", "executemany") and \
                SQL_RECEIVER_RE.search(dotted(node.func.value)) and node.args:
            self._check_sql(node, node.args[0])
        elif last in ("raw", "extra", "RawSQL") and node.args:
            q = node.args[0]
            vals = dynamic_format(q)
            if vals and re.search(r"(?i)\b(select|update|insert|delete|where|from)\b", ast.unparse(q)):
                self._check_sql(node, q)

        # --- command execution
        if name in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput"):
            if node.args and not is_const(node.args[0]):
                self.add("CG-PY-CMDI-001", node, confidence="high" if tainted_args else None)
        elif name.startswith("subprocess.") and last in ("run", "call", "Popen", "check_output", "check_call"):
            shell = kw(node, "shell")
            if shell is not None and const_val(shell) is True:
                if node.args and not is_const(node.args[0]):
                    self.add("CG-PY-CMDI-001", node, confidence="high" if tainted_args else None)
                else:
                    self.add("CG-PY-CMDI-001", node, "shell=True with constant command", severity="LOW",
                             confidence="low")

        # --- eval / exec
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec") and node.args and \
                not is_const(node.args[0]):
            self.add("CG-PY-EVAL-001", node, confidence="high" if tainted_args else None)
        elif last == "safe_eval" and route and tainted_args:
            self.add("CG-PY-EVAL-002", node)

        # --- deserialization
        if name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "marshal.loads", "marshal.load",
                    "jsonpickle.decode", "dill.loads", "shelve.open", "yaml.unsafe_load", "yaml.full_load"):
            self.add("CG-PY-DESER-001", node, confidence="high" if tainted_args else None)
        elif name in ("yaml.load", "yaml.load_all"):
            loader = kw(node, "Loader")
            if (loader is None and len(node.args) < 2) or (loader is not None and "Safe" not in dotted(loader)) or \
                    (len(node.args) >= 2 and "Safe" not in dotted(node.args[1])):
                self.add("CG-PY-DESER-001", node)

        # --- outbound HTTP
        if HTTP_LIB_RE.match(name) or name in ("urlopen", "urllib.request.urlopen"):
            v = kw(node, "verify")
            if v is not None and const_val(v) is False:
                self.add("CG-PY-TLS-001", node)
            if name.startswith("requests.") and kw(node, "timeout") is None and not self.is_test:
                self.add("CG-PY-TIMEOUT-001", node)
            url = node.args[0] if node.args else kw(node, "url")
            if url is None and last == "request" and len(node.args) > 1:
                url = node.args[1]
            if url is not None and route and self.tainted(url):
                self.add("CG-PY-SSRF-001", node, confidence="high" if route.public else "medium")

        # --- logging of sensitive data
        if isinstance(node.func, ast.Attribute) and last in LOG_METHODS and LOGGER_RE.search(dotted(node.func.value)):
            idents = set()
            for a in node.args[1:] if node.args else []:
                idents.update(identifiers(a))
            if node.args and isinstance(node.args[0], ast.JoinedStr):
                for v in node.args[0].values:
                    if isinstance(v, ast.FormattedValue):
                        idents.update(identifiers(v.value))
            for k in node.keywords:
                idents.update(identifiers(k.value))
            hits = sorted(i for i in idents if SENSITIVE_LOG_RE.search(i) and not i.endswith("_id") and i != "id")
            if hits:
                self.add("CG-PY-LOG-001", node, f"Logged value may contain sensitive data: {', '.join(hits[:4])}")

        # --- weak crypto / randomness
        if name in ("hashlib.md5", "hashlib.sha1") or (name == "hashlib.new" and node.args and
                                                       str(const_val(node.args[0], "")).lower() in ("md5", "sha1")):
            ufs = kw(node, "usedforsecurity")
            if not (ufs is not None and const_val(ufs) is False):
                ctxname = self.fn[0].name if self.fn else ""
                sev = "MEDIUM" if re.search(r"(?i)pass|pwd|secret|token|sign", ctxname + ast.unparse(node)) else None
                self.add("CG-PY-CRYPTO-001", node, severity=sev)
        if name.startswith("random.") and last in ("random", "randint", "choice", "choices", "randrange",
                                                    "getrandbits", "sample", "uniform"):
            ctxname = self.fn[0].name if self.fn else ""
            if SECURITY_VALUE_RE.search(ctxname) or SECURITY_VALUE_RE.search(self._assign_target_of(node)):
                self.add("CG-PY-CRYPTO-002", node)

        # --- path traversal
        if route and name in PATH_SINKS and tainted_args:
            self.add("CG-PY-PATH-001", node, confidence="high" if route.public else "medium")

        # --- XSS helpers
        if last == "Markup" and node.args and dynamic_format(node.args[0]):
            self.add("CG-ODOO-XSS-001", node)
        if last in ("mark_safe", "SafeString") and node.args and not is_const(node.args[0]):
            self.add("CG-PY-XSS-001", node)
        if name.endswith("fields.Html") or name == "Html":
            s = kw(node, "sanitize")
            st = kw(node, "sanitize_tags")
            if (s is not None and const_val(s) is False) or (st is not None and const_val(st) is False):
                self.add("CG-ODOO-XSS-003", node)

        # --- superuser escalation
        if last in ("with_user", "sudo") and node.args:
            a = node.args[0]
            if (isinstance(a, ast.Name) and a.id == "SUPERUSER_ID") or const_val(a) == 1 or \
                    dotted(a).endswith("SUPERUSER_ID") or dotted(a).endswith("user_root"):
                if route:
                    self.add("CG-ODOO-AUTH-001", node, "Request handled as superuser (with_user/sudo(SUPERUSER_ID))")
        if name.endswith("api.Environment") or name == "Environment":
            if len(node.args) >= 2 and (dotted(node.args[1]).endswith("SUPERUSER_ID") or const_val(node.args[1]) == 1) \
                    and route:
                self.add("CG-ODOO-AUTH-001", node, "Superuser environment created in request handler")
        if last == "env" or name.endswith(".env"):
            u = kw(node, "user")
            if u is not None and (dotted(u).endswith("SUPERUSER_ID") or const_val(u) == 1) and route:
                self.add("CG-ODOO-AUTH-001", node, "Superuser environment (env(user=SUPERUSER_ID)) in request handler")
        if last == "update_env":
            u = kw(node, "user")
            if u is not None and (dotted(u).endswith("SUPERUSER_ID") or const_val(u) == 1) and route:
                self.add("CG-ODOO-AUTH-001", node, "request.update_env(user=SUPERUSER_ID) in request handler")

        # --- version compatibility
        if self.odoo_version and self.odoo_version >= 18 and last in ("check_access_rights", "check_access_rule"):
            self.add("CG-ODOO-COMPAT-001", node)

        # --- Django/FastAPI/JWT/Flask
        if last == "add_middleware" and node.args and dotted(node.args[0]).endswith("CORSMiddleware"):
            self._check_cors_mw(node)
        if last == "CORSMiddleware":
            self._check_cors_mw(node)
        if name in ("jwt.decode",):
            opts = kw(node, "options")
            ver = kw(node, "verify")
            algs = kw(node, "algorithms")
            bad = (ver is not None and const_val(ver) is False)
            if isinstance(opts, ast.Dict):
                for k, v in zip(opts.keys, opts.values):
                    if const_val(k) == "verify_signature" and const_val(v) is False:
                        bad = True
            if algs is not None and "none" in ast.unparse(algs).lower():
                bad = True
            if bad:
                self.add("CG-PY-JWT-001", node)
        if last == "run" and dotted(node.func.value if isinstance(node.func, ast.Attribute) else node.func) in \
                ("app", "application") and const_val(kw(node, "debug")) is True:
            self.add("CG-PY-DEBUG-001", node)

        # --- hard-coded secrets in keyword args
        for k in node.keywords:
            if k.arg and SECRET_NAME_RE.search(k.arg):
                self._check_secret_value(k.value, k.arg, node)

        # --- Odoo controller sudo patterns
        if route:
            self._route_call_checks(node, route, last)

        self.generic_visit(node)

    def _assign_target_of(self, call) -> str:
        if not self.fn:
            return ""
        for n in ast.walk(self.fn[0]):
            if isinstance(n, ast.Assign) and any(c is call for c in ast.walk(n.value)):
                return " ".join(dotted(t) for t in n.targets)
        return ""

    def _check_cors_mw(self, node):
        origins = kw(node, "allow_origins")
        creds = kw(node, "allow_credentials")
        if origins is not None and '"*"' in ast.unparse(origins).replace("'", '"') and const_val(creds) is True:
            self.add("CG-PY-CORS-001", node)

    def _check_sql(self, node, q):
        vals = dynamic_format(q)
        if vals is None and isinstance(q, ast.Name) and self.fn:
            vals = self.fn[2]["fmt_vars"].get(q.id)
        if not vals:
            return
        route = self.route
        if all(safe_interp(v) for v in vals):
            self.add("CG-PY-SQLI-001", node, "SQL formatted with identifiers/placeholders only; verify none is "
                     "user-controlled", severity="LOW", confidence="low")
            return
        tainted = any(self.tainted(v) for v in vals)
        if tainted and route:
            self.add("CG-PY-SQLI-001", node, "SQL built from HTTP request input",
                     severity="CRITICAL" if route.public else "HIGH", confidence="high")
        elif tainted:
            self.add("CG-PY-SQLI-001", node, severity="HIGH", confidence="high")
        else:
            self.add("CG-PY-SQLI-001", node)

    def _check_secret_value(self, value, target_name, node):
        v = const_val(value)
        if not isinstance(v, str):
            return
        s = v.strip()
        if PLACEHOLDER_RE.match(s) or len(s) < 6:
            return
        if re.fullmatch(r"[a-z_.\-]+", s) and len(s) < 32:   # identifier-like: 'access_token', 'res.users'
            return
        if s.startswith(("http://", "https://", "/", "%(", "{")) or " " in s:
            return
        sev = "LOW" if self.is_test else None
        self.add("CG-PY-SECRET-001", node, f"Hard-coded value assigned to '{target_name}'", severity=sev)

    # ------------------------------------------------------------------ statements
    def visit_Assign(self, node):
        for t in node.targets:
            tname = dotted(t)
            leaf = tname.split(".")[-1]
            if SECRET_NAME_RE.search(leaf):
                self._check_secret_value(node.value, leaf, node)
            if tname in ("request.session.uid", "request.uid", "request.session.login"):
                self.add("CG-ODOO-AUTH-001", node, "Session identity assigned manually",
                         severity="HIGH" if self.route else "MEDIUM")
            if self.is_settings and not self.fn:
                if leaf == "DEBUG" and const_val(node.value) is True:
                    self.add("CG-PY-DJANGO-001", node, "DEBUG = True in settings")
                if leaf == "ALLOWED_HOSTS" and "'*'" in ast.unparse(node.value):
                    self.add("CG-PY-DJANGO-001", node, "ALLOWED_HOSTS allows any host")
        if isinstance(node.value, ast.Dict):
            for k, v in zip(node.value.keys, node.value.values):
                kv = const_val(k)
                if isinstance(kv, str) and SECRET_NAME_RE.search(kv):
                    self._check_secret_value(v, kv, node)
        self.generic_visit(node)

    def visit_Return(self, node):
        if self.route and node.value is not None and self.fn:
            src = ast.unparse(node.value)
            exc = self.fn[2]["exc_vars"]
            if "format_exc" in src or any(re.search(rf"\b(str|repr)\(\s*{re.escape(e)}\s*\)", src) or
                                          re.search(rf"\{{\s*{re.escape(e)}\s*[}}!:]", src) for e in exc):
                self.add("CG-ODOO-INFO-001", node)
        self.generic_visit(node)

    # ------------------------------------------------------------------ Odoo route checks
    def _route_call_checks(self, node, route, last):
        if not isinstance(node.func, ast.Attribute) or not self.has_sudo(node.func.value):
            return
        src = self.fn_source()
        has_check = any(t in src for t in ACCESS_CHECK_TOKENS) or \
            bool(re.search(r"(request\.env\.user|request\.uid|env\.user|request\.env\.uid)\b[^\n]*(==|!=|\bin\b)|"
                           r"(==|!=|\bin\b)[^\n]*(request\.env\.user|request\.uid|env\.user)", src))
        args = list(node.args) + [k.value for k in node.keywords]
        if last == "browse" and node.args and self.tainted(node.args[0]) and not has_check:
            self.add("CG-ODOO-SUDO-001", node, f"sudo().browse() with request-supplied id in auth='{route.auth}' route",
                     auth=route.auth)
        elif last in ("search", "search_read", "search_count", "search_fetch", "read_group") and \
                any(self.tainted(a) for a in args) and not has_check:
            self.add("CG-ODOO-SUDO-001", node, f"sudo().{last}() with request-controlled domain in "
                     f"auth='{route.auth}' route", auth=route.auth)
        if last in ("create", "write") and node.args:
            if self._is_raw_dict(node.args[0], self.fn[2]):
                self.add("CG-ODOO-SUDO-003", node, f"Raw request data passed to sudo().{last}()",
                         confidence="high" if route.public else "medium")
        if route.public and last in ("search_read", "read", "search", "read_group", "search_fetch", "web_search_read") \
                and (node.func.value, "SUDO-002") not in self.fn[2].setdefault("_s2", set()):
            self.fn[2]["_s2"].add((node.func.value, "SUDO-002"))
            domain = node.args[0] if node.args else kw(node, "domain")
            empty = domain is None or (isinstance(domain, ast.List) and not domain.elts)
            no_fields = last == "search_read" and len(node.args) < 2 and kw(node, "fields") is None
            if last != "read" or not node.args:
                if empty or no_fields:
                    self.add("CG-ODOO-SUDO-002", node, f"auth='{route.auth}' route: sudo().{last}() with "
                             f"{'empty domain' if empty else 'all fields'}", confidence="medium")
                elif ("CG-ODOO-SUDO-001", node.lineno) not in self.seen:
                    self.add("CG-ODOO-SUDO-002", node, f"auth='{route.auth}' route: sudo().{last}() with explicit "
                             "domain/fields - confirm only public data is returned", severity="LOW")

    def _route_checks(self, fn, route, state):
        src = ast.get_source_segment(self.text, fn) or ""
        decorator_node = fn
        if route.auth == "none" and re.search(r"request\.env\b|api\.Environment|registry\(|\.cursor\(\)", src) and \
                not any(t in src for t in SIGNATURE_TOKENS):
            self.add("CG-ODOO-AUTH-002", decorator_node, "auth='none' route accesses the ORM/database")
        state_changing = route.methods is None or any(m in ("POST", "PUT", "PATCH", "DELETE") for m in route.methods)
        if not route.csrf and not route.is_json and state_changing and route.auth != "none":
            if not any(t in src for t in SIGNATURE_TOKENS):
                self.add("CG-ODOO-CSRF-001", decorator_node,
                         f"csrf=False on type='{route.type}' auth='{route.auth}' route without request signature check")
        if route.cors and str(route.cors).strip() == "*":
            self.add("CG-ODOO-CORS-001", decorator_node, severity="HIGH" if route.auth == "user" else None)
        if re.search(r"httprequest\.files|\.files\.get(list)?\(|FileStorage", src) and \
                not any(t in src for t in UPLOAD_VALIDATION_TOKENS):
            self.add("CG-ODOO-UPLOAD-001", decorator_node)
        if route.public:
            label = " ".join(route.paths) + " " + fn.name
            if re.search(r"(?i)login|otp|reset|signup|register|verify|password|token|auth", label) and \
                    not any(t in src.lower() for t in RATE_TOKENS):
                self.add("CG-ODOO-RATE-001", decorator_node)

    def _model_method_checks(self, fn, state):
        if fn.name.startswith("_") or fn.name in ORM_OVERRIDES:
            return
        decos = state["decorators"]
        if any(d.split(".")[-1] in ("depends", "onchange", "constrains", "depends_context", "private") for d in decos):
            return
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "sudo":
                note = " (button/action method: expected public; verify sudo block is safe for every user with " \
                       "model access)" if fn.name.startswith(("action_", "button_")) else ""
                self.add("CG-ODOO-SUDO-004", n, f"Public method '{fn.name}' uses sudo(){note}", method=fn.name)
                break


def analyze(path: str, text: str, ctx: dict) -> list:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    a = Analyzer(path, text, ctx)
    a.visit(tree)
    return a.findings
