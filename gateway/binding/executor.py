"""Read-only connection, set_authorizer, limits. The only module that opens the database (I1). Spec section 5 'Execute'. Owner: Person 3.

Implemented by Person 1. A binding runs only if ``sql`` still equals the
``approved_sql`` the authorizer stored (I4); that exact string is executed. The
connection is opened read-only by URI (``mode=ro``) and carries two runtime
barriers that hold even if the static checks missed something (I5):

- ``set_authorizer``: allows SQLITE_SELECT, SQLITE_READ on the role's granted
  ``table.column`` pairs in the main database, and SQLITE_FUNCTION for allowlisted
  functions. Everything else (writes, PRAGMA, ATTACH, recursive CTEs, internal
  tables, unlisted functions) is SQLITE_DENY.
- ``set_progress_handler``: aborts the query after ``sql_controls.timeout_ms``.

The callback records every read it allows. A read the static checks did not record
(``tables``/``columns``) is an error, and the label of what SQLite actually read can
only raise the binding's label. A binding runs only for the user and policy version
it was approved for (``approved_for``). Row scope (self, department) is enforced by
the static authorizer only; SQLite's authorizer sees tables and columns, not rows.

Rows are read with ``fetchmany(max_rows + 1)`` to detect truncation. Outcome:
``resolved``, ``empty`` or ``error``; never an exception. Reasons never contain
values or database error text (I8).
"""
from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from gateway.binding.sql_validator import _schema
from gateway.models import Binding, Policy, Principal
from gateway.outbound.fill import escape_value
from gateway.policy.loader import setting

REPO_ROOT = Path(__file__).resolve().parents[2]
# Functions SQLite calls for syntax the validator accepts (LIKE, GLOB, CURRENT_*);
# they are not on sql_controls.allowed_functions because the model never calls them by name.
_SYNTAX_FUNCTIONS = frozenset({"like", "glob", "current_date", "current_time", "current_timestamp"})
_PROGRESS_STEPS = 1000  # VM instructions between deadline checks


def db_path() -> Path:
    """``ACL_DB_PATH`` if set (tests), else demo.db at the repository root."""
    return Path(os.environ.get("ACL_DB_PATH") or REPO_ROOT / "demo.db")


def _authorizer(p: Principal, policy: Policy, flags: dict[str, Any]) -> Callable[..., int]:
    """The set_authorizer callback for this principal's role. Deny by default (I6).

    Every read it allows is recorded in ``flags["reads"]`` as ``(table, column)``,
    with an empty column for a table read without column values (COUNT(*)).
    """
    role = (policy.tree.get("roles") or {}).get(p.role) or {}
    schema = _schema()
    tables: set[str] = set()
    columns: set[tuple[str, str]] = set()
    for name, grant in (role.get("tables") or {}).items():
        table = str(name).lower()
        if table not in schema or not isinstance(grant, Mapping):
            continue
        tables.add(table)
        granted = grant.get("columns")
        cols = schema[table] if granted is None else {str(c).lower() for c in granted}
        columns |= {(table, c) for c in cols}
    functions = {str(f).lower() for f in setting(policy, "sql_controls.allowed_functions")} | _SYNTAX_FUNCTIONS

    def check(action: int, arg1: str | None, arg2: str | None, dbname: str | None, source: str | None) -> int:
        try:
            if action == sqlite3.SQLITE_SELECT:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_READ and dbname in (None, "main") and arg1:
                table, column = arg1.lower(), (arg2 or "").lower()
                # An empty column name is a table read with no column values (COUNT(*)).
                if (table in tables and not column) or (table, column) in columns:
                    flags["reads"].add((table, column))
                    return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_FUNCTION and arg2 and arg2.lower() in functions:
                return sqlite3.SQLITE_OK
        except Exception:  # noqa: BLE001 - a failing check denies
            pass
        flags["denied"] = True
        return sqlite3.SQLITE_DENY

    return check


def _text(v: Any) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bytes):
        return f"<{len(v)} bytes>"
    return " ".join(str(v).splitlines())


def _cell(v: Any) -> str:
    """A markdown table cell: markdown-escaped (pipes included) whatever output_controls.escape
    says, because the table itself is markdown. Fill inserts list values unchanged."""
    return escape_value(_text(v), "markdown")


def _format(expect: str, names: list[str], rows: list[tuple[Any, ...]]) -> Any:
    if expect == "scalar":
        v = rows[0][0]
        return _text(v) if isinstance(v, bytes) else v
    if expect == "row":
        return ", ".join(f"{_text(n)}: {_text(v)}" for n, v in zip(names, rows[0]))
    lines = ["| " + " | ".join(_cell(n) for n in names) + " |", "|" + " --- |" * len(names)]
    lines += ["| " + " | ".join(_cell(v) for v in row) + " |" for row in rows]
    return "\n".join(lines)


_RANK = {"public": 0, "internal": 1, "sensitive": 2}


def _runtime_label(reads: set[tuple[str, str]], policy: Policy) -> str | None:
    """Highest label of what SQLite actually read. Unknown tables count as sensitive (fail closed)."""
    tables = (policy.tree.get("data") or {}).get("tables") or {}
    by_name = {str(k).lower(): v for k, v in tables.items()}
    label: str | None = None
    for table, column in reads:
        meta = by_name.get(table)
        if not isinstance(meta, Mapping):
            lab = "sensitive"
        else:
            cols = {str(k).lower(): v for k, v in (meta.get("columns") or {}).items()}
            lab = cols.get(column, meta.get("label", "sensitive")) if column else meta.get("label", "sensitive")
        if lab not in _RANK:
            lab = "sensitive"
        label = lab if label is None else max(label, lab, key=_RANK.__getitem__)
    return label


def _unrecorded(b: Binding, reads: set[tuple[str, str]]) -> bool:
    """True if SQLite read a table or column the static checks did not record."""
    tables = {t.lower() for t in b.tables}
    columns = {c.lower() for c in b.columns}
    return any((f"{t}.{c}" not in columns) if c else (t not in tables) for t, c in reads)


def _fail(b: Binding, reason: str) -> Binding:
    b.status, b.reason, b.value, b.rows, b.truncated = "error", reason, None, 0, False
    return b


def execute(b: Binding, p: Principal, policy: Policy) -> Binding:
    """Run exactly the validated SQL on a read-only connection; resolved, empty or error. Spec section 5 'Execute', I1, I4."""
    if b.status is not None:
        return b
    if not b.approved_sql:
        return _fail(b, "Query was not approved; not executed.")
    if b.sql != b.approved_sql:
        return _fail(b, "SQL changed after it was approved; not executed.")
    if b.approved_for != (p.user_id, policy.version_hash):
        return _fail(b, "Query was approved for another user or policy version; not executed.")
    sql = b.approved_sql
    flags: dict[str, Any] = {"denied": False, "timeout": False, "reads": set()}
    conn: sqlite3.Connection | None = None
    try:
        max_rows = int(setting(policy, "sql_controls.max_rows"))
        deadline = time.monotonic() + int(setting(policy, "sql_controls.timeout_ms")) / 1000

        def progress() -> int:
            if time.monotonic() > deadline:
                flags["timeout"] = True
                return 1
            return 0

        path = db_path()
        if not path.is_file():
            return _fail(b, "The database is not available.")
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        conn.set_authorizer(_authorizer(p, policy, flags))
        conn.set_progress_handler(progress, _PROGRESS_STEPS)
        params = {"current_user": p.user_id, "current_role": p.role, "current_department": p.department}
        cur = conn.execute(sql, params)
        # Statements are authorized while being prepared, so every read is known here,
        # before any row is fetched. SQLite's own read set must stay within what the
        # static checks recorded, and its labels can only raise the binding label.
        if _unrecorded(b, flags["reads"]):
            return _fail(b, "Query read data the static checks did not record; not returned.")
        runtime = _runtime_label(flags["reads"], policy)
        if runtime is not None:
            b.label = runtime if b.label is None else max(b.label, runtime, key=_RANK.__getitem__)  # type: ignore[assignment]
        names = [d[0] for d in cur.description or ()]
        rows = cur.fetchmany(max_rows + 1)
        b.truncated = len(rows) > max_rows
        rows = rows[:max_rows]
        b.rows = len(rows)
        if not rows or not names or (b.expect == "scalar" and rows[0][0] is None):
            b.status, b.value = "empty", None
        else:
            b.status, b.value = "resolved", _format(b.expect, names, rows)
        return b
    except Exception:  # noqa: BLE001 - never raise to the caller; never echo database error text (I8)
        if flags["timeout"]:
            return _fail(b, "Query timed out.")
        if flags["denied"]:
            return _fail(b, "Query not permitted by the database authorizer.")
        return _fail(b, "Query failed.")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Gateway-internal read for the protected-value index (spec section 4 step 9)
# ---------------------------------------------------------------------------

INDEX_TIMEOUT_S = 5.0
INDEX_MAX_ROWS = 100_000  # per column; more raises, and the output filter fails closed


def db_state() -> tuple[str, int, int]:
    """(path, mtime_ns, size) of the database file; changes when demo.db is rewritten. Raises if missing."""
    path = db_path().resolve()
    st = path.stat()
    return str(path), st.st_mtime_ns, st.st_size


def read_column_values(columns: set[tuple[str, str]]) -> dict[tuple[str, str], list[Any]]:
    """Every value of each schema ``(table, column)``, for the protected-value index. Never for a model.

    Same read-only connection and runtime barriers as ``execute``: the authorizer
    allows only SELECT and reads of exactly these columns, and the progress handler
    aborts after ``INDEX_TIMEOUT_S``. Unknown tables or columns, too many rows or any
    database error raise; the caller fails closed. Identifiers come from the schema
    file, never from a request.
    """
    schema = _schema()
    wanted = {(t.lower(), c.lower()) for t, c in columns}
    if any(t not in schema or c not in schema[t] or not (t + c).replace("_", "").isalnum() or not (t + c).isascii()
           for t, c in wanted):
        raise ValueError("Unknown table or column for the protected-value index.")
    tables = {t for t, _ in wanted}
    deadline = time.monotonic() + INDEX_TIMEOUT_S

    def check(action: int, arg1: str | None, arg2: str | None, dbname: str | None, source: str | None) -> int:
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and dbname in (None, "main"):
            table, column = (arg1 or "").lower(), (arg2 or "").lower()
            # An empty column is the table read itself, which carries no column values.
            if (table, column) in wanted or (not column and table in tables):
                return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    path = db_path()
    if not path.is_file():
        raise FileNotFoundError("The database is not available.")
    conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        conn.set_authorizer(check)
        conn.set_progress_handler(lambda: int(time.monotonic() > deadline), _PROGRESS_STEPS)
        out: dict[tuple[str, str], list[Any]] = {}
        for table, column in sorted(wanted):
            cur = conn.execute('SELECT "' + column + '" FROM "' + table + '"')  # schema identifiers, checked above
            rows = cur.fetchmany(INDEX_MAX_ROWS + 1)
            if len(rows) > INDEX_MAX_ROWS:
                raise ValueError("Too many rows for the protected-value index.")
            out[(table, column)] = [r[0] for r in rows]
        return out
    finally:
        conn.close()
