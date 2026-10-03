"""SQL validator: one read-only SELECT, allowlisted functions, gateway parameters, known schema.

Spec section 5 'Resolution of one binding' / 'Gateway parameters', section 8 'Query stage', I3, I5, I6.
Owner: Person 3.
"""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from gateway.binding import sql_validator
from gateway.binding.sql_validator import validate_sql
from gateway.models import Binding, Policy
from gateway.policy.loader import parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent


def _policy(profile: str = "strict", **sql: Any) -> Policy:
    data = copy.deepcopy(yaml.safe_load((REPO_ROOT / "policy.yaml").read_text(encoding="utf-8")))
    data["profile"] = profile
    data["sql_controls"].pop("select_star", None)  # let the profile decide
    data["sql_controls"].update(sql)
    return parse_policy(yaml.safe_dump(data).encode("utf-8"))


STRICT = _policy("strict")
BALANCED = _policy("balanced")


def _validate(sql: str, policy: Policy = STRICT) -> Binding:
    return validate_sql(Binding(name="{x1}", sql=sql, purpose="test", expect="scalar"), policy)


# ---------------------------------------------------------------------------
# Allowed
# ---------------------------------------------------------------------------


def test_simple_select_passes_and_records_tables_and_columns() -> None:
    b = _validate("SELECT salary FROM salaries WHERE employee_id = :current_user")
    assert b.status is None, b.reason
    assert b.tables == ["salaries"]
    assert b.columns == ["salaries.employee_id", "salaries.salary"]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT s.salary FROM salaries AS s WHERE s.employee_id = :current_user",
        "SELECT e.name, s.salary FROM employees e JOIN salaries s ON s.employee_id = e.id WHERE e.id = :current_user",
        "SELECT count(*) FROM employees WHERE department = :current_department",
        "SELECT department, avg(salary) FROM salaries JOIN employees ON employees.id = salaries.employee_id GROUP BY department",
        "SELECT CASE WHEN s.salary > (SELECT AVG(salary) FROM salaries) THEN 'above' ELSE 'at or below' END "
        "FROM salaries s WHERE s.employee_id = :current_user",
        "SELECT name FROM employees UNION SELECT name FROM products",
        "SELECT name FROM employees UNION ALL SELECT name FROM products ORDER BY 1",
        "WITH mine AS (SELECT salary AS s FROM salaries WHERE employee_id = :current_user) SELECT s FROM mine",
        "SELECT x.s FROM (SELECT salary AS s FROM salaries) x",
        "SELECT name FROM employees WHERE id IN (SELECT employee_id FROM salaries WHERE salary > 10000)",
        "SELECT name FROM employees WHERE EXISTS (SELECT 1 FROM salaries WHERE salaries.employee_id = employees.id)",
        "SELECT round(avg(price), 2), sum(price), min(price), max(price), abs(-1) FROM products",
        "SELECT coalesce(title, 'n/a'), ifnull(title, '-'), lower(name), upper(name), length(name) FROM employees",
        "SELECT date('now'), strftime('%Y', 'now')",
        "SELECT CAST(price AS INTEGER) FROM products",
        "SELECT name FROM employees WHERE title = :current_role OR department = :current_department",
        "SELECT salary FROM salaries WHERE employee_id = :current_user;",
        "SELECT salary -- the user's own\nFROM salaries /* comment */ WHERE employee_id = :current_user",
        'SELECT "Salary" FROM "Salaries" WHERE [employee_id] = :current_user',
        "SELECT name FROM products WHERE name LIKE 'A%' AND price BETWEEN 1 AND 10 AND category IN ('a', 'b')",
        "SELECT 1",
    ],
)
def test_read_only_selects_pass(sql: str) -> None:
    b = _validate(sql)
    assert b.status is None, b.reason


def test_columns_are_recorded_through_joins_subqueries_ctes_and_unions() -> None:
    b = _validate(
        "WITH d AS (SELECT department AS dep FROM employees WHERE id = :current_user) "
        "SELECT e.name FROM employees e JOIN d ON e.department = d.dep "
        "WHERE e.id IN (SELECT employee_id FROM salaries WHERE salary > 1) "
        "UNION SELECT name FROM products"
    )
    assert b.status is None, b.reason
    assert b.tables == ["employees", "products", "salaries"]
    assert b.columns == [
        "employees.department", "employees.id", "employees.name",
        "products.name", "salaries.employee_id", "salaries.salary",
    ]


def test_a_table_joined_without_using_its_columns_is_still_recorded() -> None:
    b = _validate("SELECT employees.id FROM employees, salaries")
    assert b.tables == ["employees", "salaries"]


def test_validation_never_changes_the_sql() -> None:
    """I4: the exact string that passed is what the executor runs."""
    sql = 'SELECT s.salary FROM "salaries" s WHERE s.employee_id = :current_user'
    assert _validate(sql).sql == sql
    assert _validate("SELECT * FROM products", BALANCED).sql == "SELECT * FROM products"


# ---------------------------------------------------------------------------
# Rejected: statements (I5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM salaries",
        "UPDATE salaries SET salary = 99999 WHERE employee_id = :current_user",
        "DROP TABLE salaries",
        "PRAGMA table_info(salaries)",
        "ATTACH DATABASE 'other.db' AS other",
        "DETACH other",
        "INSERT INTO salaries VALUES ('x', 1, 'PLN')",
        "REPLACE INTO salaries VALUES ('x', 1, 'PLN')",
        "CREATE TABLE t (a)",
        "ALTER TABLE salaries ADD COLUMN bonus INTEGER",
        "VACUUM",
        "BEGIN",
        "EXPLAIN SELECT 1",
        "ANALYZE",
        "REINDEX",
        "VALUES (1)",
        "SELECT * INTO copy FROM salaries",
        "WITH x AS (SELECT 1) DELETE FROM salaries",
        "SELECT name FROM employees EXCEPT SELECT name FROM products",
    ],
)
def test_non_select_statements_are_rejected(sql: str) -> None:
    b = _validate(sql)
    assert b.status == "rejected"
    assert b.reason


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1; DROP TABLE x",
        "SELECT 1; SELECT 2",
        "SELECT 1; -- harmless\nDROP TABLE salaries",
    ],
)
def test_stacked_statements_are_rejected(sql: str) -> None:
    assert _validate(sql).status == "rejected"


def test_recursive_cte_is_rejected() -> None:
    b = _validate("WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT n FROM r")
    assert b.status == "rejected"
    assert "recursive" in b.reason.lower()


@pytest.mark.parametrize("sql", ["", "   ", "not sql at all", "SELECT FROM WHERE", "SELECT salary FROM salaries WHERE"])
def test_unparsable_or_empty_sql_is_rejected(sql: str) -> None:
    assert _validate(sql).status == "rejected"


# ---------------------------------------------------------------------------
# Rejected: functions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT load_extension('evil.so')",
        "SELECT randomblob(1000000000)",
        "SELECT zeroblob(1000000000)",
        "SELECT sqlite_version()",
        "SELECT printf('%s', name) FROM employees",
        "SELECT name FROM employees WHERE name REGEXP 'a'",
        "SELECT row_number() OVER () FROM employees",
        "SELECT * FROM pragma_table_info('salaries')",
        "SELECT iif(1, 2, 3)",
    ],
)
def test_functions_outside_the_allowlist_are_rejected(sql: str) -> None:
    b = _validate(sql, BALANCED)  # balanced, so SELECT * is not what rejects it
    assert b.status == "rejected"


def test_the_allowlist_comes_from_the_policy() -> None:
    allowed = [f for f in STRICT.tree["sql_controls"]["allowed_functions"] if f != "avg"]
    no_avg = _policy(allowed_functions=allowed)
    assert _validate("SELECT avg(price) FROM products", no_avg).status == "rejected"
    assert _validate("SELECT avg(price) FROM products").status is None


# ---------------------------------------------------------------------------
# Rejected: parameters (I3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT salary FROM salaries WHERE employee_id = :user_id",
        "SELECT salary FROM salaries WHERE employee_id = ?",
        "SELECT salary FROM salaries WHERE employee_id = ?1",
        "SELECT salary FROM salaries WHERE employee_id = :1",
        "SELECT salary FROM salaries WHERE employee_id = @current_user",
        "SELECT salary FROM salaries WHERE employee_id = $current_user",
        "SELECT salary FROM salaries WHERE employee_id = :CURRENT_USER",
    ],
)
def test_parameters_other_than_the_gateway_ones_are_rejected(sql: str) -> None:
    assert _validate(sql).status == "rejected"


def test_unknown_parameter_reason_names_the_allowed_ones() -> None:
    b = _validate("SELECT salary FROM salaries WHERE employee_id = :user_id")
    assert ":current_user" in b.reason


# ---------------------------------------------------------------------------
# Rejected: schema
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT salary FROM payroll",
        "SELECT name FROM sqlite_master",
        "SELECT name FROM sqlite_schema",
        "SELECT salary FROM main.salaries",
        "SELECT bonus FROM salaries",
        "SELECT name FROM employees, products",  # ambiguous column
        "SELECT x.nope FROM (SELECT salary FROM salaries) x",
    ],
)
def test_unknown_tables_and_columns_are_rejected(sql: str) -> None:
    assert _validate(sql).status == "rejected"


# ---------------------------------------------------------------------------
# SELECT *: strict rejects, balanced and relaxed leave it for the authorizer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sql", ["SELECT * FROM employees", "SELECT e.* FROM employees e"])
def test_select_star_is_rejected_in_strict(sql: str) -> None:
    b = _validate(sql)
    assert b.status == "rejected"
    assert "*" in b.reason


def test_count_star_is_not_select_star() -> None:
    assert _validate("SELECT count(*) FROM employees").status is None


def test_select_star_passes_in_expand_mode_with_every_column_recorded() -> None:
    b = _validate("SELECT * FROM employees", BALANCED)
    assert b.status is None, b.reason
    assert b.columns == [f"employees.{c}" for c in ("department", "email", "id", "name", "title")]


# ---------------------------------------------------------------------------
# Fail closed, values never echoed (I6, I8)
# ---------------------------------------------------------------------------


def test_an_already_decided_binding_is_left_alone() -> None:
    b = Binding(name="{x1}", sql="SELECT 1", purpose="p", expect="scalar", status="rejected", reason="Earlier check.")
    assert validate_sql(b, STRICT).reason == "Earlier check."


def test_an_internal_error_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("internal detail 44051401359")

    monkeypatch.setattr(sql_validator.sqlglot, "parse", boom)
    b = _validate("SELECT 1")
    assert b.status == "rejected"
    assert "44051401359" not in b.reason


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT nope FROM salaries WHERE employee_id = '44051401359'",
        "SELECT secret_44051401359(1)",
        "SELECT salary FROM salaries WHERE employee_id = :p44051401359",
        "SELECT x FROM t44051401359",
    ],
)
def test_reasons_never_echo_literals_or_odd_identifiers(sql: str) -> None:
    b = _validate(sql)
    assert b.status == "rejected"
    assert "44051401359" not in b.reason


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT a.salary FROM salaries a WHERE a.employee_id = :current_user COLLATE NOCASE",
        "SELECT CURRENT_DATE",
        "SELECT name FROM employees GROUP BY name HAVING count(*) > 1 LIMIT 5 OFFSET 0",
        "select salary from SALARIES where EMPLOYEE_ID = :current_user",
    ],
)
def test_syntax_that_sqlglot_models_as_functions_passes(sql: str) -> None:
    assert _validate(sql).status is None


@pytest.mark.parametrize(
    "sql",
    [
        'SELECT "load_extension"(\'x\')',
        "SELECT LOAD_EXTENSION('x')",
        "SELECT 1 FROM salaries WHERE salary = (SELECT randomblob(9))",
        "SELECT name ->> '$.x' FROM employees",
        "SELECT salary FROM salaries WHERE employee_id = :current_user UNION SELECT name FROM sqlite_master",
        "SELECT salary FROM salaries INDEXED BY sqlite_autoindex_salaries_1",
    ],
)
def test_disguised_functions_and_tables_are_rejected(sql: str) -> None:
    assert _validate(sql).status == "rejected"


def test_unterminated_comment_is_reported_as_unparsable() -> None:
    assert _validate("SELECT 1 /* unterminated").reason == "The SQL could not be parsed."
