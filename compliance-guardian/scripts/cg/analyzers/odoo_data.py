"""Odoo data-file analyzers: XML (views/QWeb/rules/groups), ir.model.access.csv, __manifest__.py, odoo.conf."""
from __future__ import annotations

import ast
import csv
import io
import re
import xml.etree.ElementTree as ET

from . import line_of, make

SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(national_?id|identification_?id|iqama|passport|ssn|social_?sec|tax_?id|vat_?number|iban|bank_?acc|"
    r"card_?number|salary|wage|health|medical|diagnos|religion|ethnic|race|biometric|fingerprint|criminal|"
    r"genetic|blood|disabilit|password|api_?key|secret|token)")
PORTAL_GROUPS = ("base.group_portal", "base.group_public")
ADMIN_GROUPS = ("base.group_system", "base.group_erp_manager")
BROAD_GROUPS = ("base.group_user", "base.group_portal", "base.group_public")
MAX_XML = 5 * 1024 * 1024


def _line(text, needle, start=0):
    idx = text.find(needle, start)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def _refs(value: str):
    return re.findall(r"ref\(\s*['\"]([\w.]+)['\"]\s*\)", value or "")


def analyze_xml(path, text, ctx):
    out = []
    if len(text) > MAX_XML:
        return out
    # --- t-raw (regex keeps exact lines; works for QWeb/OWL templates)
    for m in re.finditer(r"\bt-raw\s*=", text):
        ln = text.count("\n", 0, m.start()) + 1
        out.append(make("CG-ODOO-XSS-002", path, ln, line_of(text, ln)))
    if re.search(r"<!(DOCTYPE|ENTITY)", text[:20000], re.I):
        return out  # never parse DTD/entities from untrusted repos (entity-expansion DoS); Odoo XML needs none
    try:
        root = ET.fromstring(text)  # noqa: S314 - DTD/entities rejected above
    except ET.ParseError:
        return out
    for rec in root.iter("record"):
        model = rec.get("model", "")
        rid = rec.get("id", "")
        fields = {f.get("name"): f for f in rec.findall("field")}
        ln = _line(text, f'id="{rid}"') if rid else 1
        if model == "ir.rule":
            dom_el = fields.get("domain_force")
            dom = (dom_el.text or dom_el.get("eval") or "") if dom_el is not None else ""
            groups_el = fields.get("groups")
            groups = _refs(groups_el.get("eval", "")) if groups_el is not None else []
            compact = re.sub(r"\s", "", dom)
            if compact in ("[(1,'=',1)]", '[(1,"=",1)]', "[]") and any(g in PORTAL_GROUPS for g in groups):
                out.append(make("CG-ODOO-RULE-001", path, ln, line_of(text, ln),
                                f"Rule '{rid}' grants all records to {', '.join(groups)}"))
            if re.search(r"user\.company_id\b", dom) and "company_ids" not in dom:
                v = ctx.get("odoo_version")
                if v is None or v >= 13:
                    out.append(make("CG-ODOO-RULE-002", path, ln, line_of(text, ln)))
        elif model == "res.groups":
            imp = fields.get("implied_ids")
            if imp is not None:
                implied = _refs(imp.get("eval", ""))
                admin = [g for g in implied if g in ADMIN_GROUPS]
                if admin:
                    broad = rid in BROAD_GROUPS or rid.split(".")[-1] in ("group_user", "group_portal", "group_public")
                    out.append(make("CG-ODOO-GROUP-001", path, ln, line_of(text, ln),
                                    f"Group '{rid}' implies {', '.join(admin)}",
                                    confidence="high" if broad else "low"))
        elif model == "res.users":
            g = fields.get("groups_id") or fields.get("group_ids")
            if g is not None and any(x in ADMIN_GROUPS for x in _refs(g.get("eval", ""))):
                out.append(make("CG-ODOO-GROUP-001", path, ln, line_of(text, ln),
                                f"Data file grants admin group to user record '{rid}'", severity="MEDIUM"))
    # --- view fields: sensitive field hidden only in UI
    for fld in root.iter("field"):
        name = fld.get("name", "")
        if fld.get("invisible") and not fld.get("groups") and SENSITIVE_FIELD_RE.search(name):
            if fld.get("invisible") not in ("0", "False"):
                ln = _line(text, f'name="{name}"')
                out.append(make("CG-ODOO-VIEW-001", path, ln, line_of(text, ln),
                                f"Field '{name}' hidden with invisible= but no groups="))
    return out


def analyze_access_csv(path, text, ctx):
    out = []
    try:
        rows = list(csv.DictReader(io.StringIO(text)))
    except csv.Error:
        return out
    for i, row in enumerate(rows, start=2):
        group = (row.get("group_id:id") or row.get("group_id") or "").strip()
        perms = {p: (row.get(f"perm_{p}") or "0").strip() in ("1", "True", "true") for p in
                 ("read", "write", "create", "unlink")}
        model = row.get("model_id:id") or row.get("model_id") or ""
        snippet = line_of(text, i)
        writes = [p for p in ("write", "create", "unlink") if perms[p]]
        if not group:
            if writes:
                out.append(make("CG-ODOO-ACL-001", path, i, snippet, f"{model}: no group with {'/'.join(writes)}"))
            elif perms["read"]:
                out.append(make("CG-ODOO-ACL-002", path, i, snippet, f"{model}: readable by every user"))
        elif group in PORTAL_GROUPS or group.endswith(("group_portal", "group_public")):
            if writes:
                out.append(make("CG-ODOO-ACL-003", path, i, snippet,
                                f"{model}: {group} granted {'/'.join(writes)}"))
    return out


def analyze_manifest(path, text, ctx):
    out = []
    try:
        data = ast.literal_eval(_strip_comments(text))
    except (ValueError, SyntaxError):
        return out
    if not isinstance(data, dict):
        return out
    v = ctx.get("odoo_version")
    ver = str(data.get("version", ""))
    if v and ver and re.match(r"^\d+\.\d+\.", ver) and not ver.startswith(f"{v}.0") and ver.count(".") >= 4:
        ln = _line(text, "version")
        out.append(make("CG-ODOO-MANIFEST-001", path, ln, line_of(text, ln),
                        f"Manifest version {ver} vs configured Odoo {v}"))
    for hook in ("uninstall_hook", "post_init_hook", "pre_init_hook"):
        if hook in data:
            ln = _line(text, hook)
            out.append(make("CG-ODOO-HOOK-001", path, ln, line_of(text, ln), f"{hook} defined: '{data[hook]}'"))
    return out


def _strip_comments(text):
    # manifests are python dict literals possibly preceded by comments / encoding lines
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith("#")]
    return "\n".join(lines)


def analyze_odoo_conf(path, text, ctx):
    out = []
    if "[options]" not in text:
        return out
    for i, raw in enumerate(text.splitlines(), 1):
        ln = raw.strip()
        m = re.match(r"(\w+)\s*=\s*(.*)$", ln)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if k == "admin_passwd" and v and not v.startswith("$pbkdf2") and v.lower() not in ("false", ""):
            out.append(make("CG-ODOO-CONF-001", path, i, raw))
        elif k == "list_db" and v.lower() in ("true", "1"):
            out.append(make("CG-ODOO-CONF-002", path, i, raw))
        elif k == "dev_mode" and v and v.lower() not in ("false", "0", ""):
            out.append(make("CG-ODOO-CONF-003", path, i, raw))
        elif k in ("db_password", "smtp_password") and v and v.lower() not in ("false", "") and not v.startswith("$"):
            out.append(make("CG-SEC-002", path, i, raw, f"{k} stored in server configuration file"))
    return out
