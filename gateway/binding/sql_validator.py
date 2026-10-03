"""Parse, SELECT only, functions, params, schema. Spec section 5 'Validate'. Owner: Person 3.

Implemented by Person 1. Every decision is made on the sqlglot AST (dialect
``sqlite``), never with a regex over the SQL text (CLAUDE.md rule 5). The schema
comes from ``db/schema.sql`` through ``gateway.llm.prompts.load_schema``, not
from the database: only the executor opens the database (I1).

A binding passes with ``status`` still None and ``tables``/``columns`` filled in
(``"table.column"`` for every base-table column used anywhere, ``SELECT *``
expanded). Any failure, including an internal error, sets ``rejected`` (I6).
The SQL string itself is never modified (I4): analysis runs on a copy.
"""
from __future__ import annotations

import re
from functools import lru_cache

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import Scope, traverse_scope

from gateway.inbound.masker import find_sensitive
from gateway.llm.prompts import load_schema
from gateway.models import Binding, Policy
from gateway.policy.loader import setting

DIALECT = "sqlite"
GATEWAY_PARAMETERS = ("current_user", "current_role", "current_department")

# Statement and clause types that are never read-only. Command is sqlglot's fallback
# for anything it does not model (ALTER, REPLACE, VACUUM, EXPLAIN, ...).
_FORBIDDEN: tuple[type[exp.Expression], ...] = tuple(
    getattr(exp, name) for name in (
        "Insert", "Update", "Delete", "Drop", "Create", "Alter", "Pragma", "Attach", "Detach", "Command",
        "Merge", "Transaction", "Commit", "Rollback", "Set", "Use", "Analyze", "Copy", "LoadData", "Into",
        "Cache", "Uncache", "Refresh", "Describe", "Show", "Grant", "Revoke", "TruncateTable",
    ) if hasattr(exp, name)
)
# Expression syntax that sqlglot (30.x) models as Func but SQLite does not call as a function.
# Found by parsing every SQLite expression form; anything else that is a Func must be allowlisted.
# The JSON operators -> and ->> also parse as Func and stay rejected (they call JSON functions).
_SYNTAX = (exp.And, exp.Or, exp.Case, exp.Cast, exp.Collate, exp.Exists,
           exp.CurrentDate, exp.CurrentTime, exp.CurrentTimestamp)
# Argument shapes tried when mapping an allowlisted name to sqlglot's expression classes.
_PROBE_ARGS = ("x", "x, y", "'%Y', x", "x, 2")


def _say(name: object) -> str:
    """An identifier for a reason, or a generic word. Display only: never used to decide anything."""
    if isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", name) and not find_sensitive(name):
        return name
    return "(name not shown)"


@lru_cache(maxsize=1)
def _schema() -> dict[str, dict[str, str]]:
    """Table -> column -> type placeholder, lower case, from db/schema.sql (read once)."""
    return {t.lower(): {c.lower(): "TEXT" for c in cols} for t, cols in load_schema().items()}


@lru_cache(maxsize=16)
def _allowed_functions(names: tuple[str, ...]) -> tuple[frozenset[type[exp.Expression]], frozenset[str]]:
    """sqlglot expression classes and plain names that the allowlisted function names parse to.

    sqlglot normalizes names (ifnull -> Coalesce, strftime -> TimeToStr), so the
    allowlist is mapped by parsing each name the same way the query is parsed.
    """
    classes: set[type[exp.Expression]] = set()
    for name in names:
        for args in _PROBE_ARGS:
            try:
                tree = sqlglot.parse_one(f"SELECT {name}({args})", read=DIALECT)
            except ParseError:
                continue
            first = tree.expressions[0] if isinstance(tree, exp.Select) and tree.expressions else None
            if isinstance(first, exp.Func) and not isinstance(first, exp.Anonymous):
                classes |= {type(f) for f in first.find_all(exp.Func) if not isinstance(f, exp.Anonymous)}
    return frozenset(classes), frozenset(n.lower() for n in names)


class _Reject(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason


def _check_function(node: exp.Func, classes: frozenset[type[exp.Expression]], names: frozenset[str]) -> None:
    if isinstance(node, _SYNTAX):
        return
    if isinstance(node, exp.If) and isinstance(node.parent, exp.Case):  # WHEN ... THEN inside CASE
        return
    if isinstance(node, exp.Anonymous):
        if node.name.lower() in names:
            return
        raise _Reject(f"Function {_say(node.name)} is not allowed.")
    if type(node) not in classes:
        raise _Reject(f"Function {_say(node.sql_name().lower())} is not allowed.")


def _check_tree(root: exp.Expression, policy: Policy) -> None:
    """Statement shape, forbidden nodes, functions, parameters, SELECT * and table names."""
    if type(root) not in (exp.Select, exp.Union):
        raise _Reject(f"Only SELECT is allowed, not {_say(type(root).__name__.upper())}.")
    classes, names = _allowed_functions(tuple(setting(policy, "sql_controls.allowed_functions")))
    reject_star = setting(policy, "sql_controls.select_star") == "reject"
    schema = _schema()
    cte_names = {c.alias_or_name.lower() for c in root.find_all(exp.CTE)}
    if cte_names & set(schema):
        raise _Reject("A CTE may not reuse the name of a table.")

    for node in root.walk():
        if isinstance(node, _FORBIDDEN):
            raise _Reject(f"{_say(type(node).__name__.upper())} is not allowed; only a read-only SELECT.")
        if isinstance(node, (exp.Except, exp.Intersect)):
            raise _Reject("Only UNION may combine SELECTs.")
        if isinstance(node, exp.With) and node.args.get("recursive"):
            raise _Reject("Recursive CTEs are not allowed.")
        if isinstance(node, exp.CTE) and type(node.this) not in (exp.Select, exp.Union):
            raise _Reject("A CTE must be a SELECT.")
        if isinstance(node, exp.Placeholder):
            if node.name not in GATEWAY_PARAMETERS:
                raise _Reject(
                    f"Parameter {':' + _say(node.name) if node.name else '?'} is not allowed; "
                    "use :current_user, :current_role or :current_department.")
        elif isinstance(node, (exp.Parameter, exp.SessionParameter)):
            raise _Reject("Only :current_user, :current_role and :current_department are allowed as parameters.")
        elif isinstance(node, exp.Func):
            _check_function(node, classes, names)
        elif isinstance(node, exp.Star) and reject_star and isinstance(node.parent, (exp.Select, exp.Column)):
            raise _Reject("SELECT * is not allowed; list the columns.")
        elif isinstance(node, exp.Table):
            if not isinstance(node.this, exp.Identifier):
                raise _Reject("Table-valued functions are not allowed.")
            if node.args.get("db") or node.args.get("catalog"):
                raise _Reject("Tables may not be qualified with a database name.")
            name = node.name.lower()
            if name not in schema and name not in cte_names:
                raise _Reject(f"Unknown table {_say(node.name)}.")


def _base_table(scope: Scope | None, alias: str) -> exp.Table | None:
    """The base table an alias refers to in this scope or an enclosing one (correlated subqueries)."""
    while scope is not None:
        source = scope.sources.get(alias)
        if source is not None:
            return source if isinstance(source, exp.Table) else None
        scope = scope.parent
    return None


def _lineage(root: exp.Expression) -> tuple[list[str], list[str]]:
    """Base tables and ``table.column`` used anywhere. Raises if a column is unknown or ambiguous."""
    tree = qualify(root.copy(), schema=_schema(), dialect=DIALECT, validate_qualify_columns=True, expand_stars=True)
    tables: set[str] = set()
    columns: set[str] = set()
    for scope in traverse_scope(tree):
        tables |= {s.name.lower() for s in scope.sources.values() if isinstance(s, exp.Table)}
        for col in scope.columns:
            table = _base_table(scope, col.table)
            if table is not None:
                columns.add(f"{table.name.lower()}.{col.name.lower()}")
    return sorted(tables), sorted(columns)


def validate_sql(b: Binding, policy: Policy) -> Binding:
    """Parse with sqlglot; set status rejected or pass the binding on. Spec section 5 'Validate', I3, I5."""
    if b.status is not None:
        return b
    try:
        try:
            statements = [s for s in sqlglot.parse(b.sql, read=DIALECT) if s is not None]
        except (ParseError, TokenError):
            raise _Reject("The SQL could not be parsed.") from None
        if len(statements) != 1:
            raise _Reject("Exactly one SELECT statement is allowed." if statements else "The SQL is empty.")
        root = statements[0]
        _check_tree(root, policy)
        try:
            b.tables, b.columns = _lineage(root)
        except _Reject:
            raise
        except Exception:  # noqa: BLE001 - qualify raises for unknown or ambiguous columns
            raise _Reject("Unknown or ambiguous column.") from None
    except _Reject as r:
        b.status, b.reason = "rejected", r.reason
    except Exception:  # noqa: BLE001 - any failure in the check rejects (I6); never echo the message
        b.status, b.reason = "rejected", "SQL validation failed internally."
    return b
