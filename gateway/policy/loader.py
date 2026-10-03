"""Load, validate, merge profile, reload by mtime, version hash. Spec section 6. Owner: Person 1.

Validation is deny by default: unknown keys, wrong types, unknown references and
any unexpected exception reject the file. Error messages name paths and expected
types, never the values in the file (I8), because the file holds API keys.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, Generic, TypeVar

import yaml

from gateway.models import ControlSource, Policy, Profile
from gateway.policy.profiles import PROFILES, STRICT_DEFAULTS

log = logging.getLogger(__name__)
T = TypeVar("T")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Core controls (spec section 6) and the policy keys that would name them.
# Any of these set to off is a validation error; they are always on.
CORE_CONTROLS: dict[str, tuple[str, ...]] = {
    "authentication": ("auth", "authentication"),
    "sql_validation": ("sql_validation", "sql_controls"),
    "authorization": ("authorization",),
    "executor": ("executor",),
    "fill": ("fill",),
    "audit": ("audit",),
}
_CORE_ALIASES = {alias: name for name, aliases in CORE_CONTROLS.items() for alias in aliases}

# Controls that may be switched off, and the key that switches them.
_TOGGLES: dict[str, str] = {
    "prompt_controls.secrets": "mode",
    "prompt_controls.pii": "mode",
    "prompt_controls.injection": "mode",
    "prompt_controls.signatures": "mode",
    "prompt_controls.tool_definitions": "mode",
    "prompt_controls.semantic": "enabled",
    "prompt_controls.history_remask": "enabled",
    "output_controls.protected_values": "enabled",
}

_BUILTIN_TOOLS = frozenset({"query_data"})
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MISSING = object()


class PolicyError(ValueError):
    """The policy file is invalid. ``problems`` lists one sentence per problem, no values."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = tuple(problems)
        super().__init__("Invalid policy: " + " ".join(problems))


# ---------------------------------------------------------------------------
# YAML: safe loader that rejects duplicate keys
# ---------------------------------------------------------------------------


class _StrictLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        try:
            duplicate = key in seen
        except TypeError:
            raise PolicyError([f"Unsupported mapping key at line {key_node.start_mark.line + 1}."]) from None
        if duplicate:
            raise PolicyError([f"Duplicate key at line {key_node.start_mark.line + 1}."])
        seen.add(key)
    return loader.construct_mapping(node, deep=True)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _read_yaml(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise PolicyError(["Policy file is not valid UTF-8."]) from None
    try:
        return yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except PolicyError:
        raise
    except yaml.MarkedYAMLError as e:
        # str(e) quotes the offending line, which may hold an API key; report the position only.
        mark = e.problem_mark or e.context_mark
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise PolicyError([f"Invalid YAML{where}."]) from None
    except yaml.YAMLError:
        raise PolicyError(["Invalid YAML."]) from None


# ---------------------------------------------------------------------------
# Schema checks. Each check returns the normalized value and appends problems.
# ---------------------------------------------------------------------------

_Check = Callable[[Any, str, list[str]], Any]


def _kind(v: Any) -> str:
    if isinstance(v, bool):
        return "a boolean"
    if isinstance(v, int):
        return "an integer"
    if isinstance(v, float):
        return "a number"
    if isinstance(v, str):
        return "a string"
    if isinstance(v, list):
        return "a list"
    if isinstance(v, dict):
        return "a mapping"
    if v is None:
        return "null"
    return "an unsupported type"


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _str() -> _Check:
    def check(v: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(v, str) or not v.strip():
            errs.append(f"{path}: expected a non-empty string, got {_kind(v)}.")
        return v
    return check


def _ident() -> _Check:
    def check(v: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(v, str) or not _IDENT.match(v):
            errs.append(f"{path}: expected an identifier (letters, digits, underscore).")
        return v
    return check


def _regex() -> _Check:
    def check(v: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(v, str):
            errs.append(f"{path}: expected a regular expression string, got {_kind(v)}.")
            return v
        try:
            re.compile(v)
        except re.error:
            errs.append(f"{path}: not a valid regular expression.")
        return v
    return check


def _int(lo: int, hi: int) -> _Check:
    def check(v: Any, path: str, errs: list[str]) -> Any:
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            errs.append(f"{path}: expected an integer from {lo} to {hi}.")
        return v
    return check


def _num(lo: float, hi: float) -> _Check:
    def check(v: Any, path: str, errs: list[str]) -> Any:
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
            errs.append(f"{path}: expected a number from {lo} to {hi}.")
            return v
        return float(v)
    return check


def _bool() -> _Check:
    def check(v: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(v, bool):
            errs.append(f"{path}: expected true or false, got {_kind(v)}.")
        return v
    return check


def _enum(*choices: Any) -> _Check:
    def check(v: Any, path: str, errs: list[str]) -> Any:
        if isinstance(v, bool) or v not in choices:
            errs.append(f"{path}: expected one of {', '.join(map(str, choices))}.")
        return v
    return check


def _mode(*choices: str) -> _Check:
    """A control mode. PyYAML reads a bare ``off`` as False; normalize it to "off"."""
    inner = _enum(*choices, "off")

    def check(v: Any, path: str, errs: list[str]) -> Any:
        return inner("off" if v is False else v, path, errs)
    return check


def _nullable(inner: _Check) -> _Check:
    def check(v: Any, path: str, errs: list[str]) -> Any:
        return None if v is None else inner(v, path, errs)
    return check


def _list(item: _Check, min_len: int = 0) -> _Check:
    def check(v: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(v, list):
            errs.append(f"{path}: expected a list, got {_kind(v)}.")
            return v
        if len(v) < min_len:
            errs.append(f"{path}: expected at least {min_len} item(s).")
        return [item(x, f"{path}[{i}]", errs) for i, x in enumerate(v)]
    return check


def _map(value: _Check, key: _Check | None = None) -> _Check:
    """Mapping with caller-chosen keys (users, roles, tables)."""
    def check(v: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(v, dict):
            errs.append(f"{path}: expected a mapping, got {_kind(v)}.")
            return v
        out: dict[str, Any] = {}
        for k, x in v.items():
            if not isinstance(k, str):
                errs.append(f"{path}: keys must be strings.")
                continue
            if key is not None:
                key(k, _join(path, k), errs)
            out[k] = value(x, _join(path, k), errs)
        return out
    return check


def _obj(fields: dict[str, _Check], required: tuple[str, ...] = ()) -> _Check:
    """Mapping with a fixed set of keys. Unknown keys are rejected."""
    def check(v: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(v, dict):
            errs.append(f"{path or 'policy'}: expected a mapping, got {_kind(v)}.")
            return v
        out: dict[str, Any] = {}
        for k, x in v.items():
            if not isinstance(k, str):
                errs.append(f"{path or 'policy'}: keys must be strings.")
            elif k not in fields:
                errs.append(f"{_join(path, k)}: unknown key.")
            else:
                out[k] = fields[k](x, _join(path, k), errs)
        for k in required:
            if k not in v:
                errs.append(f"{_join(path, k)}: required key is missing.")
        return out
    return check


def _budgets() -> _Check:
    """Fixed keys plus one optional override per role name (checked against roles later)."""
    fixed = {
        "default": _obj({
            "tokens_per_day": _int(0, 10**9),
            "requests_per_minute": _int(0, 10**6),
            "cost_per_day_usd": _num(0, 10**6),
        }),
        "count_judge_tokens": _bool(),
        "store": _str(),
    }
    per_role = _obj({
        "tokens_per_day": _int(0, 10**9),
        "requests_per_minute": _int(0, 10**6),
        "cost_per_day_usd": _num(0, 10**6),
    })

    def check(v: Any, path: str, errs: list[str]) -> Any:
        if not isinstance(v, dict):
            errs.append(f"{path}: expected a mapping, got {_kind(v)}.")
            return v
        out: dict[str, Any] = {}
        for k, x in v.items():
            if not isinstance(k, str):
                errs.append(f"{path}: keys must be strings.")
            else:
                out[k] = (fixed.get(k) or per_role)(x, _join(path, k), errs)
        return out
    return check


_LABEL = _enum("public", "internal", "sensitive")
_MODEL = _obj({
    "provider": _enum("ollama", "openai_compatible"),
    "base_url": _str(),
    "name": _str(),
    "trust": _enum("local", "external"),
    "max_tokens": _int(1, 32_768),
    "timeout_s": _num(0.1, 300),
})

_SCHEMA = _obj({
    "version": _enum(2),
    "profile": _enum("strict", "balanced", "relaxed"),
    "models": _obj({
        "answer": _MODEL,
        "judge": _MODEL,
        "allowed": _list(_obj({"name": _str(), "digest": _str()}, required=("name",))),
        "on_unlisted": _enum("block", "substitute"),
    }),
    "users": _map(
        _obj(
            {
                "api_key": _str(),
                "role": _str(),
                "department": _str(),
                "ai_data_policy": _enum("allow", "deny"),
            },
            required=("api_key", "role", "department", "ai_data_policy"),
        ),
        key=_ident(),
    ),
    "data": _obj({
        "tables": _map(
            _obj(
                {
                    "label": _LABEL,
                    "owner_column": _ident(),
                    "department_column": _ident(),
                    "identity_columns": _list(_ident()),
                    "columns": _map(_LABEL, key=_ident()),
                },
                required=("label",),
            ),
            key=_ident(),
        ),
    }),
    "roles": _map(
        _obj({
            "max_ai_data_policy": _enum("allow", "deny"),
            "max_label_to_model": _LABEL,
            "tables": _map(
                _obj({"scope": _enum("self", "department", "all"), "columns": _list(_ident(), min_len=1)},
                     required=("scope",)),
                key=_ident(),
            ),
            "tools": _map(
                _obj({
                    "args": _map(_obj({"allow_pattern": _regex()}, required=("allow_pattern",)), key=_ident()),
                    "max_label": _LABEL,
                }),
                key=_ident(),
            ),
        }),
        key=_ident(),
    ),
    "prompt_controls": _obj({
        "secrets": _obj({"mode": _mode("block", "redact", "log")}),
        "pii": _obj({
            "mode": _mode("block", "redact", "log"),
            "types": _list(_enum("email", "phone", "card", "pesel", "iban")),
        }),
        "injection": _obj({"mode": _mode("block", "log")}),
        "signatures": _obj({"mode": _mode("block", "log"), "feed": _str()}),
        "semantic": _obj({
            "enabled": _bool(),
            "block_threshold": _num(0.0, 1.0),
            "on_failure": _enum("block", "allow_and_flag"),
        }),
        "tool_definitions": _obj({"mode": _mode("block", "log")}),
        "history_remask": _obj({"enabled": _bool(), "ttl_minutes": _int(1, 7 * 24 * 60)}),
    }),
    "sql_controls": _obj({
        "allow_statements": _list(_enum("SELECT"), min_len=1),
        "allowed_functions": _list(_ident()),
        "select_star": _enum("reject", "expand"),
        "scope_enforcement": _enum("reject", "rewrite"),
        "aggregates": _enum("column_access", "separate"),
        "recursive_cte": _enum("reject"),
        "max_rows": _int(1, 10_000),
        "timeout_ms": _int(1, 60_000),
        "max_bindings_per_request": _int(1, 100),
    }),
    "tool_controls": _obj({
        "max_tool_iterations": _int(1, 20),
        "unknown_tool": _enum("deny"),
        "placeholder_egress": _enum("deny"),
    }),
    "output_controls": _obj({
        "mode": _enum("redact", "block"),  # the output filter always runs (I15)
        "echo_own_input": _bool(),
        "protected_values": _obj({"enabled": _bool(), "min_digits": _int(1, 32)}),
        "escape": _enum("markdown", "none"),
    }),
    "markers": _obj({
        "denied": _str(),
        "rejected": _str(),
        "empty": _str(),
        "error": _str(),
        "prior_value": _str(),
        "all_denied_message": _nullable(_str()),
    }),
    "budgets": _budgets(),
    "pricing_per_1k_tokens": _map(_num(0, 1000)),
    "audit": _obj({
        "path": _str(),
        "log_prompt_text": _enum("masked", "none"),
        "hash_chain": _bool(),
    }),
    "dashboard": _obj({"refresh_seconds": _int(1, 3600)}),
})


# ---------------------------------------------------------------------------
# Checks that span sections
# ---------------------------------------------------------------------------


def _is_off(v: Any) -> bool:
    if v is False or v == "off":
        return True
    return isinstance(v, dict) and (v.get("mode") in (False, "off") or v.get("enabled") in (False, "off"))


def _core_problems(data: dict[str, Any]) -> list[str]:
    """Core controls switched off at the top level or inside any section."""
    errs: list[str] = []
    candidates: list[tuple[str, Any]] = list(data.items())
    for section, body in data.items():
        if isinstance(body, dict):
            candidates += [(f"{section}.{k}", v) for k, v in body.items() if isinstance(k, str)]
    for path, value in candidates:
        name = _CORE_ALIASES.get(path.rsplit(".", 1)[-1])
        if name and _is_off(value):
            errs.append(f"{path}: {name.replace('_', ' ')} is a core control and cannot be disabled.")
    return errs


def _reference_problems(data: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    roles: dict[str, Any] = data.get("roles", {})
    tables: dict[str, Any] = data.get("data", {}).get("tables", {})

    seen_keys: set[str] = set()
    for uid, user in data.get("users", {}).items():
        if user["role"] not in roles:
            errs.append(f"users.{uid}.role: unknown role '{user['role']}'.")
        if user["api_key"] in seen_keys:
            errs.append(f"users.{uid}.api_key: duplicates the key of another user.")
        seen_keys.add(user["api_key"])

    for rname, role in roles.items():
        for tname, grant in role.get("tables", {}).items():
            path = f"roles.{rname}.tables.{tname}"
            table = tables.get(tname)
            if table is None:
                errs.append(f"{path}: unknown table '{tname}'.")
                continue
            if grant["scope"] == "self" and "owner_column" not in table:
                errs.append(f"{path}.scope: scope self needs data.tables.{tname}.owner_column.")
            if grant["scope"] == "department" and "department_column" not in table:
                errs.append(f"{path}.scope: scope department needs data.tables.{tname}.department_column.")
        for tool in role.get("tools", {}):
            if tool in _BUILTIN_TOOLS:
                errs.append(f"roles.{rname}.tools.{tool}: built-in tool name cannot be granted as a client tool.")

    for key in data.get("budgets", {}):
        if key not in ("default", "count_judge_tokens", "store") and key not in roles:
            errs.append(f"budgets.{key}: unknown role '{key}'.")
    return errs


# ---------------------------------------------------------------------------
# Merge: explicit > profile > strict default
# ---------------------------------------------------------------------------


def _merge(explicit: dict[str, Any], profile: Profile) -> tuple[dict[str, Any], dict[str, ControlSource]]:
    overrides = PROFILES[profile]
    sources: dict[str, ControlSource] = {}

    def walk(defaults: dict[str, Any], given: dict[str, Any], prefix: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, dv in defaults.items():
            path = prefix + k
            gv = given.get(k, _MISSING)
            if isinstance(dv, dict):
                out[k] = walk(dv, gv if isinstance(gv, dict) else {}, path + ".")
            elif gv is not _MISSING:
                out[k], sources[path] = gv, "explicit"
            elif path in overrides:
                out[k], sources[path] = overrides[path], "profile"
            else:
                out[k], sources[path] = dv, "default"
        # Keys with no default (users, roles, tables, per-role budgets) passed the schema.
        for k, gv in given.items():
            if k not in defaults:
                out[k] = gv
        return out

    return walk(STRICT_DEFAULTS, explicit, ""), sources


def _fill_role_defaults(tree: dict[str, Any]) -> None:
    """Missing role fields take the most restrictive value."""
    for role in tree["roles"].values():
        role.setdefault("max_ai_data_policy", "deny")
        role.setdefault("max_label_to_model", "public")
        role.setdefault("tables", {})
        role.setdefault("tools", {})
        for tool in role["tools"].values():
            tool.setdefault("args", {})


def _freeze(v: Any) -> Any:
    if isinstance(v, dict):
        return MappingProxyType({k: _freeze(x) for k, x in v.items()})
    if isinstance(v, list):
        return tuple(_freeze(x) for x in v)
    return v


def _thaw(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {k: _thaw(x) for k, x in v.items()}
    if isinstance(v, tuple):
        return [_thaw(x) for x in v]
    return v


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def parse_policy(raw: bytes) -> Policy:
    """Validate and merge policy file bytes into an immutable Policy. Raises PolicyError."""
    data = _read_yaml(raw)
    if not isinstance(data, dict):
        raise PolicyError(["Policy file must be a YAML mapping."])

    errs = _core_problems(data)
    # A core control switched off is reported once, not again as an unknown key or wrong type.
    data = {k: v for k, v in data.items() if not (k in _CORE_ALIASES and _is_off(v))}
    clean = _SCHEMA(data, "", errs)
    if not errs:
        errs = _reference_problems(clean)
    if errs:
        raise PolicyError(errs)

    profile: Profile = clean.pop("profile", "strict")
    clean.pop("version", None)
    tree, sources = _merge(clean, profile)
    _fill_role_defaults(tree)
    disabled = tuple(path for path, key in _TOGGLES.items() if setting_in(tree, f"{path}.{key}") in (False, "off"))
    return Policy(
        version_hash=hashlib.sha256(raw).hexdigest(),
        profile=profile,
        tree=_freeze(tree),
        sources=MappingProxyType(dict(sorted(sources.items()))),
        disabled_controls=disabled,
    )


def load_policy(path: str | os.PathLike[str]) -> Policy:
    """Read and parse one policy file. Raises PolicyError, including when the file is unreadable."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise PolicyError(["Policy file cannot be read."]) from None
    return parse_policy(raw)


def setting_in(tree: Mapping[str, Any], path: str) -> Any:
    node: Any = tree
    for part in path.split("."):
        node = node[part]
    return node


def setting(policy: Policy, path: str) -> Any:
    """Value at a dotted path of the merged policy, e.g. ``sql_controls.max_rows``. KeyError if absent."""
    return setting_in(policy.tree, path)


def effective_policy(policy: Policy) -> dict[str, Any]:
    """Every control with its value and source, for GET /policy/effective and the dashboard.

    Contains controls only: users, roles and API keys are not part of the view.
    """
    controls: dict[str, dict[str, Any]] = {
        path: {"value": _thaw(setting(policy, path)), "source": source}
        for path, source in policy.sources.items()
    }
    for name in CORE_CONTROLS:
        controls[f"core.{name}"] = {"value": "on", "source": "default"}
    return {
        "version": policy.version_hash,
        "profile": policy.profile,
        "controls": controls,
        "disabled_controls": list(policy.disabled_controls),
    }


def policy_path() -> Path:
    """``ACL_POLICY_PATH`` if set (tests), else the repository's policy.yaml."""
    return Path(os.environ.get("ACL_POLICY_PATH") or REPO_ROOT / "policy.yaml")


class ReloadingFile(Generic[T]):
    """The last valid parse of a file, reloaded when its mtime or size changes (spec section 6).

    Call ``snapshot()`` once at the start of each request and use the value
    unchanged until the request ends (I16). An invalid file keeps the last valid
    value; the error is kept for /health and the dashboard. An invalid file at
    startup raises: the gateway never runs without a valid file.
    Subclasses define ``_parse`` (raise ValueError with a value-free message) and ``_version``.
    """

    _label = "File"

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._error: str | None = None
        self._error_at: float | None = None
        self._stamp = self._file_stamp()
        self._value: T = self._read()
        self._loaded_at = time.time()

    @property
    def path(self) -> Path:
        return self._path

    def _parse(self, raw: bytes) -> T:
        raise NotImplementedError

    def _version(self, value: T) -> str:
        raise NotImplementedError

    def _extra_status(self, value: T) -> dict[str, Any]:
        return {}

    def _read(self) -> T:
        try:
            raw = self._path.read_bytes()
        except OSError:
            raise self._unreadable() from None
        return self._parse(raw)

    def _unreadable(self) -> ValueError:
        return ValueError(f"{self._label} cannot be read.")

    def _file_stamp(self) -> tuple[int, int] | None:
        try:
            st = self._path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def _load(self) -> None:
        """Replace the current value if the file is valid; otherwise record why. Fails closed."""
        try:
            value = self._read()
        except ValueError as e:  # parse errors carry value-free messages
            self._reject(str(e))
            return
        except Exception:  # noqa: BLE001 - any failure keeps the last valid value
            self._reject(f"{self._label} reload failed unexpectedly.")
            return
        self._value, self._loaded_at = value, time.time()
        self._error = self._error_at = None
        log.info("%s loaded: version %s.", self._label, self._version(value)[:12])

    def _reject(self, error: str) -> None:
        self._error, self._error_at = error, time.time()
        log.warning("%s rejected, keeping version %s: %s", self._label, self._version(self._value)[:12], error)

    def snapshot(self) -> T:
        """The value for one request; reloads first if the file changed."""
        with self._lock:
            stamp = self._file_stamp()
            if stamp != self._stamp:
                self._stamp = stamp
                self._load()
            return self._value

    def reload(self) -> dict[str, Any]:
        """Manual reload (POST /policy/reload), regardless of mtime. Returns ``status()``."""
        with self._lock:
            self._stamp = self._file_stamp()
            self._load()
        return self.status()

    def status(self) -> dict[str, Any]:
        """Active version and the last reload error, for /health and the dashboard."""
        with self._lock:
            return {
                "path": str(self._path),
                "version": self._version(self._value),
                "loaded_at": self._loaded_at,
                "error": self._error,
                "error_at": self._error_at,
                **self._extra_status(self._value),
            }


class PolicyStore(ReloadingFile[Policy]):
    """policy.yaml, reloaded by mtime. An invalid file at startup raises PolicyError."""

    _label = "Policy"

    def _parse(self, raw: bytes) -> Policy:
        return parse_policy(raw)

    def _unreadable(self) -> ValueError:
        return PolicyError(["Policy file cannot be read."])

    def _version(self, value: Policy) -> str:
        return value.version_hash

    def _extra_status(self, value: Policy) -> dict[str, Any]:
        return {"profile": value.profile, "disabled_controls": list(value.disabled_controls)}
