"""Scope ``department`` as Marek (sales_lead, department sales). Spec section 5 'Authorize'
and 'Execute', section 6 'Principals, roles and data'. Owner: Person 3.

Two layers: the static authorizer demands ``<alias>.department = :current_department`` as
a top-level AND conjunct on every read of a department-scoped table, and the executor
runs the query against a TEMP copy holding only the user's department, with the SQLite
authorizer refusing reads of the real table. The runtime tests bypass the static
authorizer to show the row barrier holds on its own.
"""
from __future__ import annotations

import dataclasses
import sqlite3
from pathlib import Path

import pytest

from gateway.binding.executor import execute
from gateway.models import Binding
from gateway.policy.loader import PolicyError, _thaw
from tests.test_authorizer import ANNA, MAREK, PIOTR, STRICT, _authorize, _data, _denied, _parse
from tests.test_executor import _approved_without_authorizer, _run

pytestmark = pytest.mark.usefixtures("db")


def _names(db: Path, department: str | None = None) -> set[str]:
    conn = sqlite3.connect(db)
    try:
        if department is None:
            return {r[0] for r in conn.execute("SELECT name FROM employees")}
        return {r[0] for r in conn.execute("SELECT name FROM employees WHERE department = ?", (department,))}
    finally:
        conn.close()


def _listed(b: Binding) -> set[str]:
    """Names in a one-column ``list`` value (markdown table, header and separator skipped)."""
    lines = str(b.value).splitlines()[2:]
    return {line.strip("| ").replace("\\", "") for line in lines}


# ---------------------------------------------------------------------------
# Allowed
# ---------------------------------------------------------------------------


def test_marek_lists_employees_in_his_department(db: Path) -> None:
    b = _run("SELECT name FROM employees WHERE department = :current_department", MAREK, expect="list")
    assert b.status == "resolved"
    assert _listed(b) == _names(db, "sales")
    assert b.rows == 12 and b.label == "internal"


def test_marek_counts_and_joins_within_his_department() -> None:
    assert _run("SELECT count(*) FROM employees WHERE department = :current_department", MAREK).value == 12
    b = _run("SELECT e.name FROM employees e JOIN employees m ON m.id = :current_user "
             "WHERE e.department = :current_department AND m.department = :current_department "
             "AND e.id = m.id", MAREK, expect="row")
    assert b.status == "resolved" and b.value == "name: Marek Wojcik"


def test_scope_all_and_scope_self_are_unchanged(db: Path) -> None:
    b = _run("SELECT name FROM employees", PIOTR, expect="list")
    assert b.status == "resolved" and _listed(b) == _names(db)
    assert _run("SELECT name FROM employees WHERE id = :current_user", ANNA).value == "Anna Zielinska"


# ---------------------------------------------------------------------------
# Denied by the static authorizer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sql", [
    "SELECT name FROM employees",
    "SELECT count(*) FROM employees",
    "SELECT name FROM employees WHERE department = :current_department OR 1 = 1",
    "SELECT name FROM employees WHERE department = 'hr'",
    "SELECT name FROM employees WHERE department != :current_department",
    "SELECT name FROM employees WHERE department = :current_department "
    "UNION SELECT name FROM employees",
    "SELECT e.name FROM employees e WHERE e.department = :current_department "
    "AND e.id IN (SELECT id FROM employees)",
])
def test_marek_listing_all_employees_is_denied(sql: str) -> None:
    b = _authorize(sql, MAREK)
    assert _denied(b)
    assert execute(b, MAREK, STRICT).status == "denied"  # a denied binding is never executed


@pytest.mark.parametrize("sql", [
    "SELECT name FROM employees WHERE id = 'piotr'",
    "SELECT name FROM employees WHERE department = :current_department AND id = 'piotr'",
    "SELECT name FROM employees WHERE department = :current_department OR id = 'piotr'",
    "SELECT name FROM employees WHERE department = :current_department AND id IN ('piotr', 'monika')",
])
def test_marek_reading_another_departments_employee_by_literal_id_is_denied(sql: str) -> None:
    b = _authorize(sql, MAREK)
    assert _denied(b)


def test_table_without_department_column_cannot_be_granted_department_scope() -> None:
    data = _data()
    data["roles"]["sales_lead"]["tables"]["products"] = {"scope": "department"}  # products has no department_column
    with pytest.raises(PolicyError, match="scope department needs data.tables.products.department_column"):
        _parse(data)


# ---------------------------------------------------------------------------
# Runtime row barrier: the static authorizer bypassed
# ---------------------------------------------------------------------------


def test_unfiltered_listing_that_skipped_the_authorizer_returns_only_his_department(db: Path) -> None:
    b = execute(_approved_without_authorizer("SELECT name FROM employees", expect="list", who=MAREK), MAREK, STRICT)
    assert b.status == "resolved"
    assert _listed(b) == _names(db, "sales")


def test_unfiltered_count_that_skipped_the_authorizer_counts_only_his_department() -> None:
    b = execute(_approved_without_authorizer("SELECT count(*) FROM employees", who=MAREK), MAREK, STRICT)
    assert (b.status, b.value) == ("resolved", 12)


def test_other_departments_employee_by_literal_id_is_empty_at_runtime() -> None:
    b = execute(_approved_without_authorizer("SELECT name FROM employees WHERE id = 'piotr'", who=MAREK),
                MAREK, STRICT)
    assert b.status == "empty" and b.value is None


def test_reading_the_main_table_directly_is_refused_by_sqlite_authorizer() -> None:
    """The validator rejects database-qualified names; approved anyway, the runtime still denies."""
    b = execute(_approved_without_authorizer("SELECT name FROM main.employees WHERE id = 'piotr'", who=MAREK),
                MAREK, STRICT)
    assert b.status == "error" and b.value is None
    assert "authorizer" in b.reason


def test_department_copy_does_not_change_the_database(db: Path) -> None:
    before = db.read_bytes()
    _run("SELECT name FROM employees WHERE department = :current_department", MAREK, expect="list")
    assert db.read_bytes() == before
    assert len(_names(db)) == 25


def test_invalid_department_grant_that_reaches_the_executor_fails_closed() -> None:
    """The loader refuses it; a tree built around the loader still never executes."""
    tree = _thaw(STRICT.tree)
    tree["roles"]["sales_lead"]["tables"]["products"] = {"scope": "department"}
    policy = dataclasses.replace(STRICT, tree=tree)
    b = _approved_without_authorizer("SELECT name FROM employees WHERE department = :current_department",
                                     expect="list", who=MAREK, policy=policy)
    out = execute(b, MAREK, policy)
    assert out.status == "error" and out.value is None
