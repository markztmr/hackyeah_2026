"""Executor: read-only connection, set_authorizer, progress-handler timeout, row limit, formatting.

Spec section 5 'Execute', I1, I4, I5, I6. Owner: Person 3.
Each test runs on a freshly seeded temp database (``db`` fixture sets ACL_DB_PATH).
Tests may open the database themselves to check it was not changed (I1 allows tests/).
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from gateway.binding import executor
from gateway.binding.executor import execute
from gateway.binding.sql_validator import validate_sql
from gateway.models import Binding, Policy, Principal
from tests.test_authorizer import ANNA, MAREK, PIOTR, STRICT, _authorize, _data, _parse

pytestmark = pytest.mark.usefixtures("db")


def _run(sql: str, who: Principal = ANNA, expect: str = "scalar", policy: Policy = STRICT) -> Binding:
    """The real chain: validate, authorize, execute."""
    b = _authorize(sql, who, policy)
    assert b.status is None, f"static checks refused the test query: {b.reason}"
    b.expect = expect  # type: ignore[assignment]
    return execute(b, who, policy)


def _approved_without_authorizer(sql: str, expect: str = "scalar", who: Principal = PIOTR,
                                 policy: Policy = STRICT) -> Binding:
    """A binding that reached the executor with no authorizer check: the runtime barriers must hold alone.

    Tables and columns come from the validator when it accepts the SQL (as in the real chain);
    SQL it rejects is approved anyway, to test the runtime layer on its own.
    """
    b = Binding(name="{x1}", sql=sql, purpose="test", expect=expect)  # type: ignore[arg-type]
    static = validate_sql(Binding(name="{x1}", sql=sql, purpose="test", expect=expect), policy)  # type: ignore[arg-type]
    if static.status is None:
        b.tables, b.columns = static.tables, static.columns
    b.approved_sql, b.approved_for = sql, (who.user_id, policy.version_hash)
    return b


def _count(db: Path, table: str) -> int:
    conn = sqlite3.connect(db)
    try:
        return conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Allowed reads and formatting
# ---------------------------------------------------------------------------


def test_intern_reads_own_salary_as_scalar() -> None:
    b = _run("SELECT salary FROM salaries WHERE employee_id = :current_user")
    assert b.status == "resolved"
    assert b.value == 6200
    assert b.rows == 1 and b.truncated is False
    assert b.label == "sensitive"  # set by the authorizer, kept by the executor


def test_row_renders_column_value_pairs() -> None:
    b = _run("SELECT name, department FROM employees WHERE id = :current_user", expect="row")
    assert b.status == "resolved"
    assert b.value == "name: Anna Zielinska, department: sales"


def test_list_renders_a_markdown_table() -> None:
    b = _run("SELECT name, price FROM products WHERE price > 5000 ORDER BY price DESC", expect="list")
    assert b.status == "resolved"
    assert b.value.splitlines() == [
        "| name | price |",
        "| --- | --- |",
        "| Laptop Pro 14 | 7499.0 |",
        "| Laptop Air 13 | 5299.0 |",
    ]
    assert b.rows == 2


def test_list_cells_cannot_break_the_table() -> None:
    b = _run("SELECT name || ' | x' AS n FROM products WHERE id = 1", PIOTR, expect="list")
    assert b.status == "resolved"
    assert b.value.splitlines()[2] == "| Laptop Pro 14 \\| x |"


def test_list_cells_are_markdown_escaped() -> None:
    b = _run("SELECT name FROM products WHERE category = 'gift'", expect="list")
    assert b.status == "resolved"
    assert "<script>" not in b.value and "&lt;script&gt;" in b.value


def test_gateway_parameters_are_bound_from_the_principal() -> None:
    b = _run("SELECT :current_user AS u, :current_role AS r, :current_department AS d", expect="row")
    assert b.status == "resolved"
    assert b.value == "u: anna, r: intern, d: sales"


def test_no_rows_is_empty() -> None:
    b = _run("SELECT name FROM products WHERE price < 0")
    assert b.status == "empty"
    assert b.value is None and b.rows == 0


def test_null_scalar_is_empty() -> None:
    b = _run("SELECT max(price) FROM products WHERE price < 0")
    assert b.status == "empty"
    assert b.value is None


def test_allowlisted_functions_and_like_and_current_date_work_at_runtime() -> None:
    assert _run("SELECT count(*) FROM products WHERE name LIKE 'Laptop%'").value == 2
    assert _run("SELECT round(avg(price), 2) FROM products WHERE category = 'hardware'").status == "resolved"
    assert _run("SELECT CURRENT_DATE").status == "resolved"
    assert _run("SELECT coalesce(ifnull(NULL, NULL), upper('a'))").value == "A"


# ---------------------------------------------------------------------------
# set_authorizer: the runtime barrier holds even without the static authorizer
# ---------------------------------------------------------------------------


def test_ungranted_column_that_passed_static_checks_fails_at_runtime() -> None:
    b = validate_sql(Binding(name="{x1}", sql="SELECT email FROM employees WHERE id = :current_user",
                             purpose="t", expect="scalar"), STRICT)
    assert b.status is None  # the validator alone is fine with it
    b.approved_sql, b.approved_for = b.sql, ("anna", STRICT.version_hash)  # authorizer bypassed
    out = execute(b, ANNA, STRICT)
    assert out.status == "error"
    assert out.value is None
    assert "authorizer" in out.reason


def test_runtime_grants_follow_the_role() -> None:
    assert execute(_approved_without_authorizer("SELECT title FROM employees", who=MAREK), MAREK, STRICT).status == "error"
    assert execute(_approved_without_authorizer("SELECT title FROM employees"), PIOTR, STRICT).status == "resolved"


@pytest.mark.parametrize("sql", [
    "SELECT randomblob(8)",
    "SELECT sqlite_version()",
    "SELECT load_extension('x')",
    "SELECT name FROM sqlite_master",  # the validator refuses it; approved anyway
    "SELECT printf('%d', 1)",
])
def test_unlisted_functions_and_internal_tables_fail_at_runtime(sql: str) -> None:
    b = execute(_approved_without_authorizer(sql), PIOTR, STRICT)
    assert b.status == "error"
    assert b.value is None


# ---------------------------------------------------------------------------
# Timeout and row limit
# ---------------------------------------------------------------------------

_SLOW = ("SELECT count(*) FROM products a, products b, products c, products d, "
         "products e, products f, products g, products h")  # 10^8 rows
_RECURSIVE = "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT count(*) FROM r"  # never ends


def test_slow_query_times_out() -> None:
    start = time.perf_counter()
    b = _run(_SLOW, PIOTR)
    assert time.perf_counter() - start < 3
    assert b.status == "error"
    assert "timed out" in b.reason


def test_endless_recursive_query_is_denied_by_set_authorizer() -> None:
    start = time.perf_counter()
    b = execute(_approved_without_authorizer(_RECURSIVE), PIOTR, STRICT)
    assert time.perf_counter() - start < 3
    assert b.status == "error"


def test_endless_recursive_query_times_out_even_if_set_authorizer_allowed_it(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_authorizer", lambda p, policy, flags: lambda *a: sqlite3.SQLITE_OK)
    start = time.perf_counter()
    b = execute(_approved_without_authorizer(_RECURSIVE), PIOTR, STRICT)
    assert time.perf_counter() - start < 3
    assert b.status == "error"
    assert "timed out" in b.reason


def test_timeout_follows_policy() -> None:
    data = _data()
    data["sql_controls"]["timeout_ms"] = 50
    start = time.perf_counter()
    b = _run(_SLOW, PIOTR, policy=_parse(data))
    assert time.perf_counter() - start < 1
    assert b.status == "error"


def test_sixty_rows_truncate_to_fifty() -> None:
    b = _run("SELECT a.name FROM products a, products b LIMIT 60", expect="list")
    assert b.status == "resolved"
    assert b.rows == 50 and b.truncated is True
    assert len(b.value.splitlines()) == 2 + 50


def test_exactly_fifty_rows_is_not_truncated() -> None:
    b = _run("SELECT a.name FROM products a, products b LIMIT 50", expect="list")
    assert b.rows == 50 and b.truncated is False


# ---------------------------------------------------------------------------
# Writing is impossible, even when attempted directly
# ---------------------------------------------------------------------------

_WRITES = [
    "DELETE FROM products",
    "UPDATE salaries SET salary = 1",
    "INSERT INTO products (id, name, category, price) VALUES (99, 'x', 'x', 1)",
    "DROP TABLE salaries",
    "CREATE TABLE t (a)",
    "PRAGMA writable_schema = 1",
    "ATTACH DATABASE 'other.db' AS other",
]


@pytest.mark.parametrize("sql", _WRITES)
def test_write_attempted_directly_fails_and_changes_nothing(sql: str, db: Path) -> None:
    before = (_count(db, "products"), _count(db, "salaries"))
    b = execute(_approved_without_authorizer(sql), PIOTR, STRICT)
    assert b.status == "error"
    assert (_count(db, "products"), _count(db, "salaries")) == before


@pytest.mark.parametrize("sql", _WRITES[:3])
def test_write_fails_even_if_set_authorizer_allowed_everything(
        sql: str, db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_authorizer", lambda p, policy, flags: lambda *a: sqlite3.SQLITE_OK)
    before = (_count(db, "products"), _count(db, "salaries"))
    b = execute(_approved_without_authorizer(sql), PIOTR, STRICT)
    assert b.status == "error"
    assert (_count(db, "products"), _count(db, "salaries")) == before


def test_vacuum_into_does_not_copy_the_database(tmp_path: Path) -> None:
    target = tmp_path / "copy.db"
    b = execute(_approved_without_authorizer(f"VACUUM INTO '{target.as_posix()}'"), PIOTR, STRICT)
    assert b.status == "error"
    assert not target.exists()


class _Spy:
    """Wraps the real connection and records every SQL string executed on it."""

    def __init__(self, conn: sqlite3.Connection, log: list[Any]) -> None:
        self._conn, self._log = conn, log

    def execute(self, sql: str, *args: Any) -> Any:
        self._log.append(sql)
        return self._conn.execute(sql, *args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    seen: dict[str, list[Any]] = {"connect": [], "execute": []}
    real = sqlite3.connect

    def connect(*args: Any, **kwargs: Any) -> Any:
        seen["connect"].append((args, kwargs))
        return _Spy(real(*args, **kwargs), seen["execute"])

    monkeypatch.setattr(executor.sqlite3, "connect", connect)
    return seen


def test_connection_is_opened_read_only_by_uri(spy: dict[str, list[Any]]) -> None:
    _run("SELECT name FROM products WHERE id = 1")
    (args, kwargs), = spy["connect"]
    assert kwargs.get("uri") is True
    assert str(args[0]).startswith("file:") and str(args[0]).endswith("?mode=ro")


def test_executes_exactly_the_approved_string(spy: dict[str, list[Any]]) -> None:
    sql = "select  salary from salaries where employee_id = :current_user -- mine"
    _run(sql)
    assert sql in spy["execute"]


def test_sql_changed_after_approval_is_not_executed(spy: dict[str, list[Any]]) -> None:
    b = _authorize("SELECT salary FROM salaries WHERE employee_id = :current_user")
    b.sql = "SELECT salary FROM salaries"
    out = execute(b, ANNA, STRICT)
    assert out.status == "error"
    assert spy["connect"] == [] and spy["execute"] == []


def test_binding_that_was_never_approved_is_not_executed(spy: dict[str, list[Any]]) -> None:
    b = Binding(name="{x1}", sql="SELECT name FROM products", purpose="t", expect="scalar")
    assert execute(b, ANNA, STRICT).status == "error"
    assert spy["connect"] == []


# ---------------------------------------------------------------------------
# Never raises, never echoes values
# ---------------------------------------------------------------------------


def test_already_decided_binding_is_left_alone() -> None:
    b = Binding(name="{x1}", sql="SELECT 1", purpose="t", expect="scalar", status="denied", reason="No.")
    out = execute(b, ANNA, STRICT)
    assert out.status == "denied" and out.reason == "No."


def test_missing_database_is_an_error_and_is_not_created(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = tmp_path / "nope.db"
    monkeypatch.setenv("ACL_DB_PATH", str(missing))
    b = execute(_approved_without_authorizer("SELECT 1", who=ANNA), ANNA, STRICT)
    assert b.status == "error"
    assert not missing.exists()


@pytest.mark.parametrize("sql", ["SELECT ?", "SELECT 1; SELECT 2", "SELECT FROM WHERE", ""])
def test_bad_sql_reaching_the_executor_is_an_error_not_an_exception(sql: str) -> None:
    assert execute(_approved_without_authorizer(sql, who=ANNA), ANNA, STRICT).status == "error"


def test_error_reason_never_echoes_query_values() -> None:
    b = execute(_approved_without_authorizer(
        "SELECT email FROM employees WHERE name = 'Katarzyna Nowak'", who=ANNA), ANNA, STRICT)
    assert b.status == "error"
    assert "Katarzyna" not in b.reason


# ---------------------------------------------------------------------------
# Red-team regressions: the runtime layer checks what SQLite actually read, and an
# approval is bound to the principal and policy version it was made for.
# ---------------------------------------------------------------------------


def test_runtime_reads_raise_an_under_reported_static_label() -> None:
    b = _authorize("SELECT salary FROM salaries WHERE employee_id = :current_user")
    b.label = "public"  # a static under-label, simulated
    out = execute(b, ANNA, STRICT)
    assert out.status == "resolved"
    assert out.label == "sensitive"


def test_runtime_label_uses_column_labels() -> None:
    b = _authorize("SELECT email FROM employees WHERE id = :current_user", PIOTR)
    b.label = "internal"
    assert execute(b, PIOTR, STRICT).label == "sensitive"


def test_runtime_read_the_static_check_did_not_record_is_an_error() -> None:
    b = _authorize("SELECT salary FROM salaries WHERE employee_id = :current_user")
    b.columns = ["salaries.employee_id"]  # static lineage missed salaries.salary, simulated
    out = execute(b, ANNA, STRICT)
    assert out.status == "error" and out.value is None


def test_runtime_table_read_the_static_check_did_not_record_is_an_error() -> None:
    b = _authorize("SELECT count(*) FROM products")
    b.tables = []
    assert execute(b, ANNA, STRICT).status == "error"


def test_binding_approved_for_another_user_is_not_executed(spy: dict[str, list[Any]]) -> None:
    b = _authorize("SELECT salary FROM salaries", PIOTR)
    out = execute(b, ANNA, STRICT)
    assert out.status == "error" and out.value is None
    assert spy["connect"] == []


def test_binding_approved_under_another_policy_version_is_not_executed(spy: dict[str, list[Any]]) -> None:
    data = _data()
    data["sql_controls"]["max_rows"] = 10
    other = _parse(data)
    assert other.version_hash != STRICT.version_hash
    b = _authorize("SELECT salary FROM salaries WHERE employee_id = :current_user")
    assert execute(b, ANNA, other).status == "error"
    assert spy["connect"] == []
