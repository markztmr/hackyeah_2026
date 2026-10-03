"""Authorizer: tables, columns, scope and literal identity filters for the role.

Spec section 5 'Authorize', section 6 'Principals, roles and data', I6. Owner: Person 3.
Every query first passes the real validator, so the tests exercise the chain as the loop runs it.
All queries run as Anna (intern) unless stated.
"""
from __future__ import annotations

import copy
import dataclasses
from pathlib import Path
from typing import Any

import pytest
import yaml

from gateway.binding import authorizer
from gateway.binding.authorizer import authorize
from gateway.binding.sql_validator import validate_sql
from gateway.models import Binding, Policy, Principal
from gateway.policy.loader import PolicyError, _thaw, parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent


def _data(profile: str = "strict") -> dict[str, Any]:
    data = copy.deepcopy(yaml.safe_load((REPO_ROOT / "policy.yaml").read_text(encoding="utf-8")))
    data["profile"] = profile
    data["sql_controls"].pop("select_star", None)  # let the profile decide
    return data


def _parse(data: dict[str, Any]) -> Policy:
    return parse_policy(yaml.safe_dump(data).encode("utf-8"))


STRICT = _parse(_data("strict"))
BALANCED = _parse(_data("balanced"))

ANNA = Principal(user_id="anna", role="intern", department="sales", ai_data_policy="deny")
MAREK = Principal(user_id="marek", role="sales_lead", department="sales", ai_data_policy="allow")
PIOTR = Principal(user_id="piotr", role="hr_manager", department="hr", ai_data_policy="allow")


def _authorize(sql: str, who: Principal = ANNA, policy: Policy = STRICT) -> Binding:
    b = validate_sql(Binding(name="{x1}", sql=sql, purpose="test", expect="scalar"), policy)
    assert b.status is None, f"validator rejected the test query: {b.reason}"
    return authorize(b, who, policy)


def _passes(b: Binding) -> bool:
    return b.status is None


def _denied(b: Binding) -> bool:
    return b.status == "denied" and bool(b.reason)


# ---------------------------------------------------------------------------
# Required cases
# ---------------------------------------------------------------------------


def test_intern_can_read_own_salary_with_current_user() -> None:
    b = _authorize("SELECT salary FROM salaries WHERE employee_id = :current_user")
    assert _passes(b)
    assert b.label == "sensitive"


def test_intern_cannot_read_ceo_salary_by_employee_id_literal() -> None:
    assert _denied(_authorize("SELECT salary FROM salaries WHERE employee_id = 1"))


def test_intern_cannot_read_salary_by_string_identity_literal() -> None:
    assert _denied(_authorize("SELECT salary FROM salaries WHERE employee_id = 'ceo'"))


def test_intern_cannot_filter_employees_by_name_literal() -> None:
    assert _denied(_authorize("SELECT id FROM employees WHERE name = 'CEO'"))


def test_intern_cannot_add_name_literal_even_next_to_own_filter() -> None:
    b = _authorize("SELECT id FROM employees WHERE id = :current_user AND name = 'CEO'")
    assert _denied(b)
    assert "CEO" not in b.reason


def test_current_user_filter_under_or_is_denied() -> None:
    assert _denied(_authorize("SELECT salary FROM salaries WHERE employee_id = :current_user OR 1=1"))


def test_filter_only_inside_subquery_with_unfiltered_outer_reference_is_denied() -> None:
    assert _denied(_authorize(
        "SELECT salary FROM salaries WHERE employee_id IN "
        "(SELECT employee_id FROM salaries WHERE employee_id = :current_user) OR 1=1"))
    assert _denied(_authorize(
        "SELECT s.salary FROM salaries s WHERE EXISTS "
        "(SELECT 1 FROM salaries t WHERE t.employee_id = :current_user)"))


def test_join_employees_to_salaries_without_filter_on_salaries_is_denied() -> None:
    assert _denied(_authorize(
        "SELECT e.name, s.salary FROM employees e JOIN salaries s ON s.employee_id = e.id "
        "WHERE e.id = :current_user"))


def test_join_with_both_references_filtered_passes() -> None:
    b = _authorize(
        "SELECT e.name, s.salary FROM employees e JOIN salaries s ON s.employee_id = e.id "
        "WHERE e.id = :current_user AND s.employee_id = :current_user")
    assert _passes(b)
    assert b.label == "sensitive"


def test_union_with_an_unfiltered_branch_is_denied() -> None:
    assert _denied(_authorize(
        "SELECT salary FROM salaries WHERE employee_id = :current_user "
        "UNION SELECT salary FROM salaries"))


def test_union_with_every_branch_filtered_passes() -> None:
    assert _passes(_authorize(
        "SELECT salary FROM salaries WHERE employee_id = :current_user "
        "UNION ALL SELECT salary FROM salaries WHERE employee_id = :current_user"))


def test_avg_salary_over_all_rows_is_denied() -> None:
    assert _denied(_authorize("SELECT AVG(salary) FROM salaries"))


def test_intern_cannot_select_email_column_not_granted() -> None:
    b = _authorize("SELECT email FROM employees WHERE id = :current_user")
    assert _denied(b)
    assert "email" in b.reason


def test_hr_manager_reads_any_salary_with_label_sensitive() -> None:
    b = _authorize("SELECT salary FROM salaries WHERE employee_id = 'anna'", PIOTR)
    assert _passes(b)
    assert b.label == "sensitive"
    assert _passes(_authorize("SELECT AVG(salary) FROM salaries", PIOTR))


# ---------------------------------------------------------------------------
# Scope self: top-level AND conjunct of the WHERE or JOIN ON at the same level
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sql", [
    "SELECT salary FROM salaries WHERE :current_user = employee_id",
    "SELECT s.salary FROM salaries AS s WHERE s.employee_id = :current_user",
    "SELECT salary FROM salaries WHERE salary > 0 AND employee_id = :current_user AND currency = 'PLN'",
    "SELECT salary FROM salaries WHERE (employee_id = :current_user AND salary > 0)",
    "SELECT salary FROM salaries WHERE (employee_id = :current_user)",
    "SELECT SALARY FROM SALARIES WHERE EMPLOYEE_ID = :current_user",
    "SELECT salary AS s FROM salaries WHERE employee_id = :current_user ORDER BY s",
    "SELECT e.name, s.salary FROM employees e JOIN salaries s "
    "ON s.employee_id = e.id AND s.employee_id = :current_user WHERE e.id = :current_user",
    "SELECT e.name, s.salary FROM employees e LEFT JOIN salaries s "
    "ON s.employee_id = :current_user WHERE e.id = :current_user",
    "SELECT COUNT(*) FROM salaries WHERE employee_id = :current_user",
    "WITH mine AS (SELECT salary FROM salaries WHERE employee_id = :current_user) SELECT salary FROM mine",
    "SELECT name FROM products",
    "SELECT 1",
])
def test_intern_queries_with_a_proper_self_filter_pass(sql: str) -> None:
    assert _passes(_authorize(sql))


@pytest.mark.parametrize("sql", [
    "SELECT salary FROM salaries WHERE NOT (employee_id <> :current_user)",
    "SELECT salary FROM salaries WHERE CASE WHEN employee_id = :current_user THEN 1 ELSE 1 END",
    "SELECT salary FROM salaries WHERE employee_id = :current_user AND 1=1 OR 1=1",
    "SELECT salary FROM salaries WHERE employee_id = :current_department",
    "SELECT salary FROM salaries WHERE employee_id = :current_role",
    "SELECT salary FROM salaries WHERE employee_id <> :current_user",
    "SELECT salary FROM salaries WHERE employee_id >= :current_user",
    "SELECT salary FROM salaries WHERE salary = :current_user",
    "SELECT salary FROM salaries WHERE employee_id = :current_user COLLATE NOCASE",
    "SELECT salary FROM salaries WHERE employee_id IN (:current_user, employee_id)",
    "SELECT salary FROM salaries HAVING employee_id = :current_user",
    "SELECT salary FROM salaries",
])
def test_self_filter_that_is_not_a_top_level_and_equality_is_denied(sql: str) -> None:
    assert _denied(_authorize(sql))


def test_left_join_on_does_not_filter_the_left_table() -> None:
    assert _denied(_authorize(
        "SELECT s.salary FROM salaries s LEFT JOIN products p ON s.employee_id = :current_user"))


def test_filter_on_another_alias_does_not_cover_the_reference() -> None:
    assert _denied(_authorize(
        "SELECT b.salary FROM salaries a JOIN salaries b ON a.salary = b.salary "
        "WHERE a.employee_id = :current_user"))


def test_unfiltered_table_in_correlated_subquery_is_denied() -> None:
    assert _denied(_authorize(
        "SELECT s.salary FROM salaries s WHERE s.employee_id = :current_user "
        "AND s.salary < (SELECT MAX(t.salary) FROM salaries t)"))


def test_comparison_few_shot_is_denied_for_intern_because_avg_reads_all_salaries() -> None:
    assert _denied(_authorize(
        "SELECT CASE WHEN s.salary > (SELECT AVG(salary) FROM salaries) THEN 'above' ELSE 'below' END "
        "FROM salaries s WHERE s.employee_id = :current_user"))


def test_unfiltered_table_inside_cte_is_denied_even_if_outer_query_filters() -> None:
    assert _denied(_authorize(
        "WITH t AS (SELECT employee_id, salary FROM salaries) "
        "SELECT salary FROM t WHERE employee_id = :current_user"))


def test_filter_outside_a_derived_table_does_not_cover_the_inner_reference() -> None:
    b = _authorize(
        "SELECT x.salary FROM (SELECT employee_id, salary FROM salaries) x "
        "WHERE x.employee_id = :current_user")
    assert _denied(b)
    assert ":current_user" in b.reason


def test_derived_table_and_union_cte_with_filters_pass() -> None:
    assert _passes(_authorize(
        "SELECT x.salary FROM (SELECT salary FROM salaries WHERE employee_id = :current_user) x"))
    assert _passes(_authorize(
        "WITH u AS (SELECT salary FROM salaries WHERE employee_id = :current_user "
        "UNION SELECT price FROM products) SELECT salary FROM u ORDER BY salary"))


def test_unused_cte_is_still_checked() -> None:
    assert _denied(_authorize(
        "WITH t AS (SELECT salary FROM salaries) "
        "SELECT salary FROM salaries WHERE employee_id = :current_user"))


# ---------------------------------------------------------------------------
# Scope department
# ---------------------------------------------------------------------------


def test_sales_lead_reads_own_department_with_label_internal() -> None:
    b = _authorize("SELECT name FROM employees WHERE department = :current_department", MAREK)
    assert _passes(b)
    assert b.label == "internal"


def test_sales_lead_without_department_filter_is_denied() -> None:
    assert _denied(_authorize("SELECT name FROM employees", MAREK))
    assert _denied(_authorize("SELECT name FROM employees WHERE department = 'hr'", MAREK))
    assert _denied(_authorize(
        "SELECT name FROM employees WHERE department = :current_department OR 1=1", MAREK))


def test_department_filter_does_not_satisfy_self_scope() -> None:
    assert _denied(_authorize("SELECT name FROM employees WHERE department = :current_department"))


def test_table_without_department_column_cannot_use_department_scope() -> None:
    data = _data()
    data["roles"]["sales_lead"]["tables"]["salaries"] = {"scope": "department"}
    with pytest.raises(PolicyError):  # the loader refuses it ...
        _parse(data)
    tree = _thaw(STRICT.tree)  # ... and the authorizer still denies if such a tree reaches it
    tree["roles"]["sales_lead"]["tables"]["salaries"] = {"scope": "department"}
    policy = dataclasses.replace(STRICT, tree=tree)
    assert _denied(_authorize(
        "SELECT salary FROM salaries WHERE employee_id = :current_user", MAREK, policy))
    assert _denied(_authorize(
        "SELECT salary FROM salaries WHERE employee_id = :current_department", MAREK, policy))


def test_sales_lead_extra_non_identity_literal_passes() -> None:
    assert _passes(_authorize(
        "SELECT name FROM employees WHERE department = :current_department AND department = 'sales'", MAREK))


# ---------------------------------------------------------------------------
# Literal identity filters: allowed only with scope all
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sql", [
    "SELECT name FROM employees WHERE department = :current_department AND name = 'CEO'",
    "SELECT name FROM employees WHERE department = :current_department AND id = 'anna'",
    "SELECT name FROM employees WHERE department = :current_department AND name LIKE 'C%'",
    "SELECT name FROM employees WHERE department = :current_department AND lower(name) = 'ceo'",
    "SELECT name FROM employees WHERE department = :current_department AND name IN ('CEO', 'CFO')",
    "SELECT name FROM employees WHERE department = :current_department AND name IS 'CEO'",
    "SELECT name FROM employees WHERE department = :current_department AND name BETWEEN 'A' AND 'B'",
    "SELECT name FROM employees WHERE department = :current_department AND 'CEO' = name",
    "SELECT COUNT(CASE WHEN name = 'CEO' THEN 1 END) FROM employees WHERE department = :current_department",
    "SELECT name FROM employees WHERE department = :current_department ORDER BY name = 'CEO'",
    "WITH t AS (SELECT name AS n FROM employees WHERE department = :current_department) "
    "SELECT n FROM t WHERE n = 'CEO'",
    "SELECT x.n FROM (SELECT name AS n FROM employees WHERE department = :current_department) x "
    "WHERE x.n = 'CEO'",
    # regressions found by probing: comparisons that are not sqlglot Predicates
    "SELECT COUNT(CASE name WHEN 'CEO' THEN 1 END) FROM employees WHERE department = :current_department",
    "SELECT max(name, 'M') FROM employees WHERE department = :current_department",
    "SELECT min(name, 'M') FROM employees WHERE department = :current_department",
    "SELECT name FROM employees WHERE department = :current_department AND name = (SELECT 'CEO')",
])
def test_identity_column_compared_to_literal_is_denied_without_scope_all(sql: str) -> None:
    b = _authorize(sql, MAREK)
    assert _denied(b)
    assert "literal" in b.reason  # denied by this rule, not by an internal error
    assert "CEO" not in b.reason and "anna" not in b.reason


def test_exists_with_select_1_is_not_a_literal_identity_filter() -> None:
    assert _passes(_authorize(
        "SELECT e.name FROM employees e WHERE e.department = :current_department AND EXISTS "
        "(SELECT 1 FROM salaries s WHERE s.employee_id = e.id AND s.employee_id = :current_user)", MAREK))


def test_scope_all_may_filter_identity_by_literal() -> None:
    b = _authorize("SELECT title FROM employees WHERE name = 'CEO'", PIOTR)
    assert _passes(b)
    assert b.label == "internal"


def test_literal_on_identity_of_unrestricted_table_passes_for_intern() -> None:
    assert _passes(_authorize("SELECT price FROM products WHERE name = 'Laptop'"))


# ---------------------------------------------------------------------------
# Columns: every use counts, SELECT * expanded in expand mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sql", [
    "SELECT name FROM employees WHERE id = :current_user AND email IS NOT NULL",
    "SELECT name FROM employees WHERE id = :current_user ORDER BY title",
    "SELECT COUNT(*) FROM employees WHERE id = :current_user GROUP BY title",
    "SELECT COUNT(email) FROM employees WHERE id = :current_user",
    "SELECT name FROM employees WHERE id = :current_user GROUP BY name HAVING MAX(title) IS NOT NULL",
    "SELECT e.name FROM employees e JOIN employees f ON f.email = e.email "
    "WHERE e.id = :current_user AND f.id = :current_user",
    "SELECT name FROM employees WHERE id = :current_user AND id IN "
    "(SELECT id FROM employees WHERE id = :current_user AND title IS NOT NULL)",
])
def test_ungranted_column_used_anywhere_is_denied(sql: str) -> None:
    assert _denied(_authorize(sql))


def test_table_not_granted_to_role_is_denied() -> None:
    data = _data()
    del data["roles"]["intern"]["tables"]["products"]
    assert _denied(_authorize("SELECT name FROM products", ANNA, _parse(data)))


def test_unknown_role_is_denied() -> None:
    ghost = Principal(user_id="anna", role="ghost", department="sales", ai_data_policy="deny")
    assert _denied(_authorize("SELECT name FROM products", ghost))


def test_select_star_in_expand_mode_checks_every_column() -> None:
    assert _denied(_authorize("SELECT * FROM employees WHERE id = :current_user", ANNA, BALANCED))
    assert _passes(_authorize("SELECT * FROM salaries WHERE employee_id = :current_user", ANNA, BALANCED))
    b = _authorize("SELECT * FROM employees", PIOTR, BALANCED)
    assert _passes(b)
    assert b.label == "sensitive"  # email is labelled sensitive


# ---------------------------------------------------------------------------
# Label
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("sql", "who", "label"), [
    ("SELECT name FROM products", ANNA, "public"),
    ("SELECT 1", ANNA, "public"),
    ("SELECT name FROM employees WHERE id = :current_user", ANNA, "internal"),
    ("SELECT COUNT(*) FROM employees", PIOTR, "internal"),
    ("SELECT email FROM employees", PIOTR, "sensitive"),
    ("SELECT COUNT(*) FROM salaries", PIOTR, "sensitive"),
    ("SELECT p.name FROM products p JOIN employees e ON e.name = p.name", PIOTR, "internal"),
])
def test_label_is_the_highest_label_read(sql: str, who: Principal, label: str) -> None:
    b = _authorize(sql, who)
    assert _passes(b)
    assert b.label == label


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------


def test_already_decided_binding_is_left_alone() -> None:
    b = Binding(name="{x1}", sql="SELECT salary FROM salaries", purpose="t", expect="scalar",
                status="rejected", reason="Validator said no.")
    out = authorize(b, ANNA, STRICT)
    assert out.status == "rejected" and out.reason == "Validator said no."


def test_unparsable_sql_reaching_the_authorizer_is_denied() -> None:
    b = authorize(Binding(name="{x1}", sql="SELECT FROM WHERE (", purpose="t", expect="scalar"), ANNA, STRICT)
    assert b.status == "denied"


def test_internal_error_denies_with_internal_error_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("secret value 6200 must not leak")
    monkeypatch.setattr(authorizer, "qualify", boom)
    b = _authorize("SELECT salary FROM salaries WHERE employee_id = :current_user")
    assert b.status == "denied"
    assert "internal error" in b.reason
    assert "6200" not in b.reason


def test_authorizer_never_changes_the_sql() -> None:
    sql = "select s.salary from salaries s where s.employee_id = :current_user"
    assert _authorize(sql).sql == sql
