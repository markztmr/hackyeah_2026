"""Tables, columns, scope, literal identity. Spec section 5 'Authorize'. Owner: Person 3.

Implemented by Person 1. Runs after ``validate_sql`` on the same SQL string, parsed
again with sqlglot (CLAUDE.md rule 5) and qualified on a copy, so every column
carries the alias of the table reference it reads and ``SELECT *`` is expanded
from the schema. The SQL string itself is never changed (I4).

Every base-table reference in every scope (FROM, JOIN, subqueries, CTEs, each
UNION branch) is checked against the role:

- the role grants the table, and every column read anywhere is in its column list;
- scope ``self`` / ``department``: the WHERE, or the ON of an inner join (or of the
  LEFT JOIN that brings in this table), of the SELECT that holds the reference has
  ``<alias>.<column> = :current_user`` / ``:current_department`` as a top-level AND
  conjunct. Only AND (and grouping parentheses) are walked, never OR, NOT or CASE;
- an identity column compared to a literal is denied unless the scope is ``all``.
  Columns are traced through CTEs and derived tables to their base columns.

A pass leaves ``status`` None, sets ``label`` to the highest label read and
``approved_sql`` to the exact string checked, which the executor compares (I4). Any
failure, including an exception, sets ``denied`` (I6). Reasons name tables,
columns and roles from the policy only, never values from the query.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import Scope, traverse_scope

from gateway.binding.sql_validator import DIALECT, _schema, validate_sql
from gateway.models import Binding, Label, Policy, Principal

_RANK: dict[str, int] = {"public": 0, "internal": 1, "sensitive": 2}
_SCOPE_PARAM = {"self": ("owner_column", "current_user"), "department": ("department_column", "current_department")}
_INTERNAL = "Authorization failed: internal error."
# Constant forms sqlglot parses (x'..' is HexString, not Literal).
CONSTANT_NODES: tuple[type[exp.Expression], ...] = tuple(
    getattr(exp, name) for name in (
        "Literal", "HexString", "BitString", "ByteString", "RawString", "National", "UnicodeString",
    ) if hasattr(exp, name)
)


class _Deny(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason


def _conjuncts(cond: exp.Expression | None) -> list[exp.Expression]:
    """Top-level AND conjuncts. Walks only AND and grouping parentheses."""
    if cond is None:
        return []
    if isinstance(cond, exp.And):
        return _conjuncts(cond.left) + _conjuncts(cond.right)
    if isinstance(cond, exp.Paren):
        return _conjuncts(cond.this)
    return [cond]


def _filters(select: exp.Select, node: exp.Table) -> list[exp.Expression]:
    """Conjuncts that restrict the rows of this table reference within its SELECT.

    WHERE always counts. The ON of an inner join filters every table joined so far;
    the ON of a LEFT JOIN filters only the table that join brings in. RIGHT and FULL
    joins never count (fail closed).
    """
    where = select.args.get("where")
    out = _conjuncts(where.this if where is not None else None)
    for join in select.args.get("joins") or []:
        on = join.args.get("on")
        side = (join.side or "").upper()
        if on is None:
            continue
        if not side or (side == "LEFT" and join.this is node):
            out += _conjuncts(on)
    return out


def _is_param(e: exp.Expression, name: str) -> bool:
    return isinstance(e, exp.Placeholder) and e.name == name


def _is_column(e: exp.Expression, alias: str, column: str) -> bool:
    return isinstance(e, exp.Column) and e.table == alias and e.name.lower() == column


def _has_scope_filter(filters: list[exp.Expression], alias: str, column: str, param: str) -> bool:
    for f in filters:
        if isinstance(f, exp.EQ) and (
            (_is_column(f.left, alias, column) and _is_param(f.right, param))
            or (_is_column(f.right, alias, column) and _is_param(f.left, param))
        ):
            return True
    return False


class _Analysis:
    """Qualified copy of the query plus helpers to resolve columns to base tables."""

    def __init__(self, sql: str) -> None:
        statements = [s for s in sqlglot.parse(sql, read=DIALECT) if s is not None]
        if len(statements) != 1:
            raise _Deny(_INTERNAL)
        self.tree = qualify(statements[0].copy(), schema=_schema(), dialect=DIALECT,
                            validate_qualify_columns=True, expand_stars=True)
        self.scopes = list(traverse_scope(self.tree))
        self.scope_of: dict[int, Scope] = {}
        self.scope_by_query: dict[int, Scope] = {id(scope.expression): scope for scope in self.scopes}
        for scope in self.scopes:
            for col in scope.columns:
                self.scope_of[id(col)] = scope

    def source(self, scope: Scope, alias: str) -> exp.Table | Scope | None:
        """What an alias names in this scope or an enclosing one (correlated subqueries)."""
        s: Scope | None = scope
        while s is not None:
            if alias in s.sources:
                found = s.sources[alias]
                return found if isinstance(found, (exp.Table, Scope)) else None
            s = s.parent
        return None

    def _resolve(self, col: exp.Column) -> tuple[exp.Table | None, list[exp.Expression]]:
        """The base table a column reads, or the projections that feed it (CTE, derived table,
        output alias). UNION columns are positional, so every branch's projection feeds them."""
        scope = self.scope_of.get(id(col))
        if scope is None:  # unqualified reference to an output column (ORDER BY total)
            query = col.find_ancestor(exp.Select, exp.Union)
            scope = self.scope_by_query.get(id(query))
            if col.table or scope is None:
                raise _Deny(_INTERNAL)
            return None, self._projections(scope, col.name)
        src = self.source(scope, col.table)
        if isinstance(src, exp.Table):
            return src, []
        if isinstance(src, Scope):
            return None, self._projections(src, col.name)
        raise _Deny(_INTERNAL)

    def _projections(self, scope: Scope, name: str) -> list[exp.Expression]:
        if not isinstance(scope.expression, (exp.Select, exp.Union)):
            raise _Deny(_INTERNAL)
        positions = [i for i, n in enumerate(scope.expression.named_selects) if n == name]
        if not positions:
            raise _Deny(_INTERNAL)
        out: list[exp.Expression] = []
        pending, steps = [scope], 0
        while pending:
            steps += 1
            if steps > 256:
                raise _Deny(_INTERNAL)
            s = pending.pop()
            if isinstance(s.expression, exp.Union):  # every branch feeds the column
                if not s.set_operation_scopes:
                    raise _Deny(_INTERNAL)
                pending.extend(s.set_operation_scopes)
                continue
            if not isinstance(s.expression, exp.Select):
                raise _Deny(_INTERNAL)
            selects = s.expression.selects
            for i in positions:
                if i >= len(selects):
                    raise _Deny(_INTERNAL)
                out.append(selects[i])
        return out

    def origins(self, col: exp.Column, depth: int = 0) -> set[tuple[str, str]]:
        """Base ``(table, column)`` pairs a column reads, traced through CTEs and derived tables."""
        if depth > 32:
            raise _Deny(_INTERNAL)
        table, projections = self._resolve(col)
        if table is not None:
            return {(table.name.lower(), col.name.lower())}
        out: set[tuple[str, str]] = set()
        for proj in projections:
            for c in proj.find_all(exp.Column):
                out |= self.origins(c, depth + 1)
        return out

    def contains_constant(self, node: exp.Expression, depth: int = 0) -> bool:
        """A constant anywhere in the node, or fed into it by a CTE or derived-table column
        (``JOIN (SELECT 'X' AS v) x ON e.name = x.v``). Hex and other string forms count."""
        if depth > 32:
            raise _Deny(_INTERNAL)
        for n in node.walk():
            if isinstance(n, CONSTANT_NODES):
                return True
            if isinstance(n, exp.Column):
                table, projections = self._resolve(n)
                if table is None and any(self.contains_constant(p, depth + 1) for p in projections):
                    return True
        return False


def _is_comparison(node: exp.Expression) -> bool:
    """A node that compares its operands. EXISTS only tests for rows; its subquery's own
    comparisons are checked where they are. Simple CASE (``CASE x WHEN 'a'``) and
    two-argument min/max compare too."""
    if isinstance(node, exp.Exists):
        return False
    if isinstance(node, exp.Predicate):
        return True
    if isinstance(node, exp.Case):
        return node.args.get("this") is not None
    if isinstance(node, (exp.Max, exp.Min)):
        return bool(node.expressions)
    return isinstance(node, (exp.Greatest, exp.Least))


def _role(policy: Policy, p: Principal) -> Mapping[str, Any]:
    role = (policy.tree.get("roles") or {}).get(p.role)
    if not isinstance(role, Mapping):
        raise _Deny(f"Role {p.role} is not defined in the policy.")
    return role


def _check(b: Binding, p: Principal, policy: Policy) -> Label:
    role = _role(policy, p)
    grants: Mapping[str, Any] = role.get("tables") or {}
    tables: Mapping[str, Any] = (policy.tree.get("data") or {}).get("tables") or {}
    # Defense in depth: never approve what the validator would reject (statement type,
    # functions, parameters), even if a caller skipped validation.
    shape = validate_sql(Binding(name=b.name, sql=b.sql, purpose="", expect=b.expect), policy)
    if shape.status is not None:
        raise _Deny(shape.reason or "The SQL did not pass validation.")
    a = _Analysis(b.sql)

    cte_names = {c.alias_or_name.lower() for c in a.tree.find_all(exp.CTE)}
    if cte_names & set(_schema()):
        raise _Deny("A CTE may not reuse the name of a table.")

    def grant(table: str) -> Mapping[str, Any]:
        g = grants.get(table)
        if not isinstance(g, Mapping) or table not in tables:
            raise _Deny(f"Role {p.role} may not read table {table}.")
        return g

    def scope_name(table: str) -> str:
        return str(grant(table).get("scope"))

    # Every Table node must be a known source of some scope: base tables are checked
    # below, CTE and derived-table references resolve to their own scopes.
    seen_tables: set[int] = set()
    label = "public"
    read_tables: set[str] = set()
    read_columns: set[tuple[str, str]] = set()

    for scope in a.scopes:
        for alias, (node, source) in scope.selected_sources.items():
            if isinstance(node, exp.Table):
                seen_tables.add(id(node))
            if not isinstance(source, exp.Table):
                continue
            table = source.name.lower()
            g = grant(table)
            read_tables.add(table)
            scope_kind = g.get("scope")
            if scope_kind == "all":
                continue
            if scope_kind not in _SCOPE_PARAM:
                raise _Deny(f"Scope of table {table} is not valid.")
            key, param = _SCOPE_PARAM[scope_kind]
            column = tables[table].get(key)
            if not column:
                raise _Deny(f"Table {table} has no {key}, so scope {scope_kind} cannot be used.")
            select = scope.expression
            if not isinstance(select, exp.Select) or not _has_scope_filter(
                    _filters(select, node), alias, str(column).lower(), param):
                raise _Deny(
                    f"Every read of table {table} needs WHERE {table}.{column} = :{param} "
                    "as a top-level AND condition.")

    for node in a.tree.find_all(exp.Table):
        if id(node) not in seen_tables:
            raise _Deny(_INTERNAL)

    for col in a.tree.find_all(exp.Column):
        for table, column in a.origins(col):
            g = grant(table)
            allowed = g.get("columns")
            if allowed is not None and column not in {str(c).lower() for c in allowed}:
                raise _Deny(f"Role {p.role} may not read column {table}.{column}.")
            read_columns.add((table, column))

    for star in a.tree.find_all(exp.Star):
        if not isinstance(star.parent, exp.Count):
            raise _Deny(_INTERNAL)  # every SELECT * must have been expanded by qualify

    # Literal identity filters: any comparison that reads an identity column of a table
    # whose scope is not 'all' and contains a literal anywhere (subqueries included).
    for pred in a.tree.walk():
        if not _is_comparison(pred):
            continue
        if not a.contains_constant(pred):
            continue
        for col in pred.find_all(exp.Column):
            for table, column in a.origins(col):
                identity = {str(c).lower() for c in tables[table].get("identity_columns") or ()}
                if column in identity and scope_name(table) != "all":
                    raise _Deny(
                        f"Comparing {table}.{column} to a literal needs scope all; "
                        "use :current_user or :current_department.")

    for table, column in read_columns:
        meta = tables[table]
        column_labels: dict[str, str] = {}  # case-insensitive, like SQLite; the higher label wins
        for name, lab in (meta.get("columns") or {}).items():
            key = str(name).lower()
            column_labels[key] = max(column_labels.get(key, lab), lab, key=_RANK.__getitem__)
        label = max(label, column_labels.get(column, meta["label"]), key=_RANK.__getitem__)
    for table in read_tables - {t for t, _ in read_columns}:
        label = max(label, tables[table]["label"], key=_RANK.__getitem__)
    return label  # type: ignore[return-value]


def authorize(b: Binding, p: Principal, policy: Policy) -> Binding:
    """Check tables, columns and scope for the role; set status denied or pass. Spec section 5 'Authorize', I6."""
    if b.status is not None:
        return b
    try:
        sql = b.sql
        label = _check(b, p, policy)
        if b.sql != sql:  # changed while being checked: approve nothing (I4)
            raise _Deny(_INTERNAL)
        b.label, b.approved_sql, b.approved_for = label, sql, (p.user_id, policy.version_hash)
    except _Deny as d:
        b.status, b.reason, b.label, b.approved_sql = "denied", d.reason, None, ""
        b.approved_for = ("", "")
    except Exception:  # noqa: BLE001 - any failure in the check denies (I6); never echo the message
        b.status, b.reason, b.label, b.approved_sql = "denied", _INTERNAL, None, ""
        b.approved_for = ("", "")
    return b
