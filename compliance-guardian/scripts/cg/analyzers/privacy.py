"""Personal-data inventory and privacy checks.

Classification is name/label heuristic only. The category labels are engineering hints;
whether a field is "sensitive"/"special category" under a specific law is a legal
classification and must be confirmed (GDPR Art. 9/10 and each national law define
their own categories).
"""
from __future__ import annotations

import ast
import re

from . import line_of, make
from .python_ast import dotted, kw, const_val

CATEGORIES = [
    # (category, sensitive?, regex)  -- order matters: first match wins
    ("credentials", True, r"password|passwd|pin_code|otp|api_?key|secret|token"),
    ("health", True, r"health|medical|diagnos|disease|illness|blood|allerg|disabilit|vaccin|pregnan|sick_?leave"),
    ("biometric", True, r"biometric|fingerprint|face_?(id|template|encoding)|iris|voice_?print"),
    ("genetic", True, r"genetic|dna"),
    ("religion_belief", True, r"religio|faith|sect\b|belief"),
    ("ethnicity_race", True, r"ethnic|race\b|racial|tribe|tribal"),
    ("political", True, r"politic|party_?member"),
    ("trade_union", True, r"trade_?union|union_?member"),
    ("sex_life_orientation", True, r"sexual|orientation"),
    ("criminal", True, r"criminal|conviction|offen[cs]e|police_?record"),
    ("national_identifier", False, r"national_?id|identification_?id|iqama|passport|ssn|social_?sec|id_?number|"
                                   r"civil_?id|residen(t|cy)_?(id|permit)|border_?number"),
    ("financial", False, r"iban|bank_?acc|acc_?number|card_?number|credit_?card|salary|wage|income|credit_?score"),
    ("location", False, r"gps|latitude|longitude|geo_?loc|home_?address|current_?location"),
    ("date_of_birth", False, r"birth|dob\b|birthday|age\b"),
    ("gender", False, r"gender|\bsex\b"),
    ("nationality", False, r"nationality|citizenship|country_of_birth"),
    ("family", False, r"marital|spouse|children|dependents?|parent_?unknown"),
    ("contact", False, r"e?mail|phone|mobile|whatsapp|fax"),
    ("online_identifier", False, r"ip_?address|device_?id|imei|mac_?address|cookie_?id|session_?id"),
    ("image", False, r"photo|avatar|image_1920|selfie"),
    ("name", False, r"(first|last|full|middle|family|given)_?name"),
]
_COMPILED = [(c, s, re.compile(r"(?i)(^|_|\b)(" + rx + r")")) for c, s, rx in CATEGORIES]
FIELD_TYPES = {"Char", "Text", "Html", "Date", "Datetime", "Binary", "Image", "Integer", "Float", "Monetary",
               "Selection", "Many2one", "Json", "CharField", "TextField", "EmailField", "DateField",
               "DateTimeField", "IntegerField", "DecimalField", "BinaryField", "ImageField", "FileField",
               "GenericIPAddressField", "JSONField"}


def classify(name: str, label: str = ""):
    for cat, sens, rx in _COMPILED:
        if rx.search(name) or (label and rx.search(label.replace(" ", "_"))):
            return cat, sens
    return None, False


def analyze_python(path, text, ctx, inventory: list):
    out = []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return out
    for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
        model = None
        for st in cls.body:
            if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ("_name", "_inherit")
                                                  for t in st.targets):
                v = const_val(st.value)
                model = model or (v if isinstance(v, str) else None)
        for st in cls.body:
            if not (isinstance(st, ast.Assign) and isinstance(st.value, ast.Call) and len(st.targets) == 1 and
                    isinstance(st.targets[0], ast.Name)):
                continue
            ftype = dotted(st.value.func).split(".")[-1]
            if ftype not in FIELD_TYPES:
                continue
            fname = st.targets[0].id
            label = const_val(kw(st.value, "string"), "") or (const_val(st.value.args[0], "") if st.value.args and
                                                              ftype not in ("Many2one", "Selection") else "")
            cat, sensitive = classify(fname, label if isinstance(label, str) else "")
            if not cat:
                continue
            groups = kw(st.value, "groups")
            tracking = kw(st.value, "tracking")
            related = kw(st.value, "related")
            entry = dict(path=path, line=st.lineno, model=model or cls.name, field=fname, type=ftype, category=cat,
                         sensitive_hint=sensitive, groups=const_val(groups) if groups is not None else None,
                         tracked=bool(tracking is not None and const_val(tracking) not in (False, None)),
                         related=const_val(related) if related is not None else None)
            inventory.append(entry)
            snippet = line_of(text, st.lineno)
            if sensitive and cat != "credentials" and groups is None:
                out.append(make("CG-PRIV-001", path, st.lineno, snippet,
                                f"{entry['model']}.{fname} looks like '{cat}' data and has no groups= restriction",
                                category_hint=cat))
            if entry["tracked"] and (sensitive or cat in ("national_identifier", "financial")):
                out.append(make("CG-ODOO-PRIV-002", path, st.lineno, snippet,
                                f"{entry['model']}.{fname} ({cat}) is tracked in chatter"))
    return out


RETENTION_RE = re.compile(r"(?i)(anonymi[sz]|pseudonymi[sz]|retention|purge|gdpr|erase|erasure|forget|"
                          r"data_?subject|_cron_.*(clean|delete|unlink|vacuum)|autovacuum)")


def has_retention_signal(text: str) -> bool:
    return bool(RETENTION_RE.search(text))
