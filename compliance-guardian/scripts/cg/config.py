"""Load and validate .compliance-guardian.yaml and the compliance/ evidence files."""
from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parents[2]
CONFIG_NAME = ".compliance-guardian.yaml"

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - PyYAML missing
    yaml = None


def load_data(path: Path):
    text = Path(path).read_text(encoding="utf-8")
    if str(path).endswith(".json"):
        return json.loads(text)
    if yaml is None:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            raise RuntimeError(f"PyYAML is not installed; cannot parse {path}. Install with: python3 -m pip install --user pyyaml")
    return yaml.safe_load(text)


def find_project_root(start: Path) -> Path:
    start = start.resolve()
    if start.is_file():
        start = start.parent
    for p in [start, *start.parents]:
        if (p / CONFIG_NAME).exists() or (p / ".git").exists():
            return p
    return start


def load_config(root: Path):
    """Returns (config_dict_or_None, errors_list)."""
    p = root / CONFIG_NAME
    if not p.exists():
        return None, []
    try:
        cfg = load_data(p) or {}
    except Exception as e:  # noqa: BLE001
        return None, [f"cannot parse {CONFIG_NAME}: {e}"]
    errors = validate(cfg)
    return apply_profiles(cfg, errors), errors


def apply_profiles(cfg: dict, errors: list) -> dict:
    """Profiles select frameworks to evaluate and supply defaults for keys the project left unset.
    They never record a legal applicability determination."""
    if not isinstance(cfg, dict):
        return cfg
    selected = []
    for name in cfg.get("profiles") or []:
        p = SKILL_DIR / "profiles" / f"{name}.yaml"
        if not p.exists():
            errors.append(f"profiles: unknown profile '{name}'")
            continue
        prof = load_data(p) or {}
        selected += prof.get("frameworks") or []
        for k, v in (prof.get("config_defaults") or {}).items():
            if k not in cfg or cfg[k] in (None, [], {}):
                cfg[k] = v
    cfg["_profile_frameworks"] = sorted(set(selected))
    return cfg


def validate(cfg: dict) -> list:
    schema_path = SKILL_DIR / "schema" / "compliance-guardian.schema.json"
    errors = []
    try:
        import jsonschema  # type: ignore
        schema = json.loads(schema_path.read_text())
        v = jsonschema.Draft202012Validator(schema)
        for err in sorted(v.iter_errors(_jsonable(cfg)), key=lambda e: list(e.path)):
            loc = "/".join(str(x) for x in err.path) or "<root>"
            errors.append(f"{loc}: {err.message}")
    except ImportError:
        if not isinstance(cfg, dict):
            errors.append("<root>: must be a mapping")
        elif "schema_version" not in cfg:
            errors.append("<root>: 'schema_version' is required")
    return errors


def _jsonable(o):
    if isinstance(o, dict):
        return {str(k): _jsonable(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_jsonable(v) for v in o]
    if isinstance(o, (_dt.date, _dt.datetime)):
        return o.isoformat()
    return o


def load_optional(root: Path, rel: str) -> dict:
    p = root / rel
    if not p.exists():
        return {}
    try:
        return load_data(p) or {}
    except Exception:  # noqa: BLE001
        return {}


def as_date(v):
    if isinstance(v, _dt.datetime):
        return v.date()
    if isinstance(v, _dt.date):
        return v
    try:
        return _dt.date.fromisoformat(str(v))
    except (TypeError, ValueError):
        return None


def odoo_version(cfg) -> int | None:
    if not cfg:
        return None
    v = (cfg.get("project") or {}).get("odoo_version")
    try:
        return int(str(v).split(".")[0]) if v else None
    except ValueError:
        return None


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "true", "yes")
