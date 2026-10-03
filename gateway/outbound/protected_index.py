"""Values the user may not see, for the output filter. Spec section 4 step 9, section 8. Owner: Person 2.

Per role: the numeric values of every column the role may not read (table or column
not granted) or that is labelled ``sensitive``. A model that writes such a number
itself (a guess, a hallucination, something it remembered) gets it redacted from the
model-written part of the answer; the same value inserted by the gateway from an
authorized binding is kept (the filter checks model spans only).

Numbers are compared in a normal form: spaces and thousands separators removed
("48,000", "48 000", "48.000" -> "48000"), a decimal part kept without trailing zeros.
Values with fewer than ``output_controls.protected_values.min_digits`` digits are
ignored. Text values are not indexed; secrets and PII have their own detectors.

The database is read through ``executor.read_column_values`` (I1). The index is built
at startup (``warm``) and rebuilt when demo.db changes (path, mtime, size) or the
policy version changes. Values never appear in repr, logs or decisions (I8).
"""
from __future__ import annotations

import logging
import math
import re
import threading
from collections.abc import Mapping
from typing import Any

from gateway.binding.executor import db_state, read_column_values
from gateway.binding.sql_validator import _schema
from gateway.models import Policy
from gateway.policy.loader import setting

log = logging.getLogger(__name__)

# A number as text: digits, optional thousands groups (space, nbsp, comma or dot), optional decimal part.
NUMBER = re.compile(r"(?<!\d)(?<!\d[.,])\d+(?:[ \u00a0.,]\d{3})*(?:[.,]\d+)?(?!\d)(?![.,]\d)")
_GROUPED = re.compile(r"(\d+(?:[.,]\d{3})*)(?:[.,](\d+))?")
_LAST_SEP = re.compile(r"(.*)[.,](\d+)")


def _canon(integer: str, decimals: str = "") -> str:
    integer = re.sub(r"[.,]", "", integer).lstrip("0") or "0"
    decimals = decimals.rstrip("0")
    return integer + "." + decimals if decimals else integer


def normalize_number(value: Any) -> set[str]:
    """Normal forms of a number (several when "48.000" could be 48000 or 48); empty if not a number."""
    if isinstance(value, bool):
        return set()
    if isinstance(value, int):
        return {str(value).lstrip("-")}
    if isinstance(value, float):
        if not math.isfinite(value):
            return set()
        whole, _, frac = format(abs(value), "f").partition(".")
        return {_canon(whole, frac)}
    if not isinstance(value, str):
        return set()
    s = value.strip()
    if not NUMBER.fullmatch(s):
        return set()
    s = s.replace(" ", "").replace("\u00a0", "")
    forms = set()
    m = _GROUPED.fullmatch(s)
    if m:  # every 3-digit group after a separator is thousands; a different tail is the decimal part
        forms.add(_canon(m.group(1), m.group(2) or ""))
    m = _LAST_SEP.fullmatch(s)
    if m:  # the last separator is the decimal point
        forms.add(_canon(m.group(1), m.group(2)))
    else:
        forms.add(_canon(s))
    return forms


def _digits(form: str) -> int:
    return sum(ch.isdigit() for ch in form)


def _text_forms(token: str) -> set[str]:
    """Normal forms of a number found in text, plus every run of consecutive thousands groups,
    so a value cannot hide by gluing 3-digit groups onto it ("48000 100", "48,000,100")."""
    forms = normalize_number(token)
    groups = re.split(r"[ \u00a0.,](?=\d{3}(?!\d))", token)  # thousands groups only, never a decimal part
    for i in range(len(groups)):
        for j in range(i + 1, len(groups) + 1):
            forms |= normalize_number("".join(groups[i:j]))
    return forms


def find_protected(text: str, values: frozenset[str], min_digits: int) -> list[tuple[int, int]]:
    """``(start, end)`` of every number in ``text`` whose normal form is in ``values``."""
    if not values:
        return []
    return [(m.start(), m.end()) for m in NUMBER.finditer(text)
            if any(f in values and _digits(f) >= min_digits for f in _text_forms(m.group(0)))]


# ---------------------------------------------------------------------------
# Index store
# ---------------------------------------------------------------------------


def _label(table: str, column: str, policy: Policy) -> str:
    tables = (policy.tree.get("data") or {}).get("tables") or {}
    meta = {str(k).lower(): v for k, v in tables.items()}.get(table)
    if not isinstance(meta, Mapping):
        return "sensitive"  # unknown: fail closed
    columns = {str(k).lower(): v for k, v in (meta.get("columns") or {}).items()}
    return str(columns.get(column, meta.get("label", "sensitive")))


def protected_columns(role: str, policy: Policy) -> set[tuple[str, str]]:
    """Schema columns the role may not read, or that are sensitive."""
    grants = {str(k).lower(): v for k, v in (((policy.tree.get("roles") or {}).get(role) or {}).get("tables") or {}).items()}
    out = set()
    for table, cols in _schema().items():
        grant = grants.get(table)
        granted = grant.get("columns") if isinstance(grant, Mapping) else []
        readable = set(cols) if granted is None else {str(c).lower() for c in granted or []}
        out |= {(table, c) for c in cols if c not in readable or _label(table, c, policy) == "sensitive"}
    return out


class _Store:
    """Column values per database state and role sets per (state, policy version, role, min_digits)."""

    __slots__ = ("_lock", "_state", "_columns", "_roles")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: tuple[str, int, int] | None = None
        self._columns: dict[tuple[str, str], frozenset[str]] = {}
        self._roles: dict[tuple[str, str, int], frozenset[str]] = {}

    def __repr__(self) -> str:
        return f"ProtectedIndex(columns={len(self._columns)}, roles={len(self._roles)})"

    __str__ = __repr__

    def values(self, role: str, policy: Policy) -> frozenset[str]:
        min_digits = int(setting(policy, "output_controls.protected_values.min_digits"))
        with self._lock:
            state = db_state()
            if state != self._state:
                raw = read_column_values({(t, c) for t, cols in _schema().items() for c in cols})
                self._columns = {col: frozenset(f for v in vals for f in normalize_number(v)) for col, vals in raw.items()}
                self._roles = {}
                self._state = state
                log.info("Protected-value index built: %d columns.", len(self._columns))
            key = (policy.version_hash, role, min_digits)
            if key not in self._roles:
                self._roles[key] = frozenset(
                    f for col in protected_columns(role, policy) for f in self._columns.get(col, ())
                    if _digits(f) >= min_digits)
            return self._roles[key]


_STORE = _Store()


def protected_values(role: str, policy: Policy) -> frozenset[str]:
    """Normal forms the role's answers must not contain in model-written text. Raises if the index cannot be built."""
    return _STORE.values(role, policy)


def warm(policy: Policy) -> None:
    """Build the index at startup for every role in the policy; a failure is logged and retried per request."""
    try:
        for role in (policy.tree.get("roles") or {}):
            protected_values(str(role), policy)
    except Exception as e:  # noqa: BLE001 - the output filter fails closed until the index builds
        log.warning("Protected-value index not built at startup (%s).", type(e).__name__)
