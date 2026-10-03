"""Red-team findings against gateway/binding/authorizer.py. Spec section 5 'Authorize', I6, I10.

Every test here FAILS on the current code and demonstrates one bypass. Do not mark them
xfail: each one is a regression test to keep once the bug is fixed (CLAUDE.md testing rules).
Ranked by severity, highest first.
"""
from __future__ import annotations

from typing import Any

import pytest

from gateway.binding.authorizer import authorize
from gateway.models import Binding, Policy
from gateway.policy.loader import PolicyError
from tests.test_authorizer import ANNA, MAREK, PIOTR, STRICT, _authorize, _data, _denied, _parse


def _label_with_column_labels(columns: dict[str, str]) -> tuple[Policy | None, str | None]:
    """Parse a policy whose employees table carries these column labels. (None, None) if the loader refuses it."""
    data: dict[str, Any] = _data()
    data["data"]["tables"]["employees"]["columns"] = columns
    try:
        policy = _parse(data)
    except PolicyError:
        return None, None
    return policy, _authorize("SELECT email FROM employees WHERE id = 'anna'", PIOTR, policy).label


# ---------------------------------------------------------------------------
# F1 (medium-high): column label lookup is case-sensitive and unchecked, so a label
# silently falls back to the lower table label. Piotr's role has max_label_to_model
# internal, so the email (meant to be sensitive) is disclosed to the model (I9, I10).
# ---------------------------------------------------------------------------


def test_mixed_case_column_label_key_still_labels_email_sensitive() -> None:
    # SQLite column names are case-insensitive and the loader accepts "Email" as an identifier,
    # but authorizer.py looks the label up with the lower-cased column name only.
    policy, label = _label_with_column_labels({"Email": "sensitive"})
    assert policy is None or label == "sensitive", (
        "email read by hr_manager was labelled internal and would be disclosed to the model")


def test_column_label_for_a_column_that_does_not_exist_is_refused() -> None:
    # A typo in data.tables.<t>.columns is accepted and ignored: the real column keeps the
    # table label. Deny by default (I6) means the policy must be rejected, or the read
    # must not be labelled lower than intended.
    policy, label = _label_with_column_labels({"emial": "sensitive"})
    assert policy is None or label == "sensitive", (
        "unknown column in a label map was ignored; email was labelled internal")


# ---------------------------------------------------------------------------
# F2 (low): the literal identity filter rule (spec section 5: comparing an identity
# column to a literal is allowed only with scope all) is detected by looking for an
# exp.Literal node inside the comparison. Constants that are not exp.Literal, or that
# sit in another scope, slip through. Scope department is still enforced, so no row
# outside Marek's department is read; the targeting rule itself fails open.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sql", [
    # hex blob cast to text: HexString, not Literal
    "SELECT id FROM employees WHERE department = :current_department "
    "AND name = CAST(x'4d6172656b20576f6a63696b' AS TEXT)",
    # literal moved into a derived table; the comparison itself holds only columns
    "SELECT e.id FROM employees e JOIN (SELECT 'Marek Wojcik' AS v) x ON e.name = x.v "
    "WHERE e.department = :current_department",
    # same through a CTE
    "WITH c AS (SELECT 'Marek Wojcik' AS v) SELECT e.id FROM employees e, c "
    "WHERE e.department = :current_department AND e.name = c.v",
])
def test_identity_column_compared_to_a_disguised_constant_is_denied_without_scope_all(sql: str) -> None:
    b = _authorize(sql, MAREK)
    assert _denied(b)


# ---------------------------------------------------------------------------
# F3 (low, defense in depth): authorize() does not check the statement type. Anything
# without a table node passes, including statements that write or load code. Today only
# the call order in agency/loop.py (validate first) stops it, and the executor's
# set_authorizer barrier is not implemented yet (executor.execute raises
# NotImplementedError). Deny by default (I5, I6) says the authorizer should not approve it.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sql", [
    "PRAGMA writable_schema=1",
    "ATTACH DATABASE 'x.db' AS x",
    "VACUUM INTO 'copy.db'",
    "SELECT load_extension('evil')",
])
def test_authorizer_alone_denies_statements_that_are_not_read_only_selects(sql: str) -> None:
    b = authorize(Binding(name="{x1}", sql=sql, purpose="t", expect="scalar"), ANNA, STRICT)
    assert b.status == "denied"
