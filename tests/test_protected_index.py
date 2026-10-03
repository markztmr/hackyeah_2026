"""Protected-value index and the output filter. Spec section 4 step 9, section 8 'Model writes a sensitive value directly'.

Owner: Person 2. Per role: numeric values from columns the role may not read or that
are sensitive, normalized (no spaces, commas or thousands dots), at least
``output_controls.protected_values.min_digits`` digits. Only model-written text is
redacted; gateway-inserted values are authorized by construction.
"""
from __future__ import annotations

import copy
import sqlite3
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from gateway.agency import loop
from gateway.binding.authorizer import authorize
from gateway.binding.disclosure import disclose
from gateway.binding.executor import execute
from gateway.binding.sql_validator import validate_sql
from gateway.llm.client import StubModel, text, tool_call
from gateway.models import FilledText, Policy, Principal, Span
from gateway.outbound import protected_index
from gateway.outbound.output_filter import REDACTED, filter_output
from gateway.outbound.protected_index import find_protected, normalize_number, protected_values
from gateway.policy.loader import parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
ANNA = Principal("anna", "intern", "sales", "deny")
MAREK = Principal("marek", "sales_lead", "sales", "allow")
PIOTR = Principal("piotr", "hr_manager", "hr", "allow")
CEO_SALARY = "48000"      # katarzyna, salaries (sensitive)
LAPTOP_PRICE = "7499"     # products.price (public, readable by every role)


def _policy(**output: Any) -> Policy:
    data = copy.deepcopy(yaml.safe_load((REPO_ROOT / "policy.yaml").read_text(encoding="utf-8")))
    for key, value in output.items():
        data["output_controls"][key] = value
    return parse_policy(yaml.safe_dump(data).encode("utf-8"))


POLICY = _policy()


def model_text(t: str) -> FilledText:
    return FilledText(text=t, spans=[Span(0, len(t), "model")])


# ---------------------------------------------------------------------------
# The index
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw, canonical", [
    ("48000", "48000"), ("48,000", "48000"), ("48 000", "48000"), ("48.000", "48000"), ("48\u00a0000", "48000"),
    ("1,234,567", "1234567"), ("48000.0", "48000"), ("129.50", "129.5"), ("7,499.00", "7499"),
])
def test_numbers_are_normalized(raw: str, canonical: str) -> None:
    assert canonical in normalize_number(raw)


@pytest.mark.parametrize("value", [48000, 48000.0, "48000"])
def test_database_values_normalize_like_text(value: Any) -> None:
    assert normalize_number(value) == {"48000"}


def test_anna_index_holds_salaries_and_unreadable_columns_but_not_prices(db: Path) -> None:
    values = protected_values(ANNA.role, POLICY)
    assert CEO_SALARY in values and "6200" in values
    assert LAPTOP_PRICE not in values


def test_sensitive_values_are_protected_even_for_roles_that_may_read_them(db: Path) -> None:
    assert CEO_SALARY in protected_values(PIOTR.role, POLICY)  # salaries are sensitive
    assert CEO_SALARY in protected_values(MAREK.role, POLICY)


def test_short_values_are_ignored(db: Path) -> None:
    values = protected_values(ANNA.role, _policy(protected_values={"enabled": True, "min_digits": 6}))
    assert CEO_SALARY not in values  # 5 digits


def test_unknown_role_protects_every_numeric_value(db: Path) -> None:
    values = protected_values("ghost", POLICY)
    assert CEO_SALARY in values and LAPTOP_PRICE in values


def test_index_is_rebuilt_when_the_database_changes(db: Path) -> None:
    assert "123456" not in protected_values(ANNA.role, POLICY)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE salaries SET salary = 123456 WHERE employee_id = 'katarzyna'")
    assert "123456" in protected_values(ANNA.role, POLICY)
    assert CEO_SALARY not in protected_values(ANNA.role, POLICY)


def test_find_protected_matches_any_formatting_as_a_whole_number() -> None:
    values = frozenset({CEO_SALARY})
    t = "a 48,000 b 48 000 c 48.000 d 148000 e 480001 f 48000.5"
    found = [t[s:e] for s, e in find_protected(t, values, 4)]
    assert found == ["48,000", "48 000", "48.000"]


# ---------------------------------------------------------------------------
# Output filter: model-written spans only
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("guess", ["48000", "48,000", "48 000", "48.000"])
def test_model_guessing_the_ceo_salary_is_redacted_for_anna(db: Path, guess: str) -> None:
    out, d = filter_output(model_text("The CEO earns " + guess + " PLN."), ANNA, POLICY)
    assert out == "The CEO earns " + REDACTED + " PLN."
    assert d.verdict == "redact" and "protected value" in d.reason and guess not in d.reason


def test_same_number_inserted_by_the_gateway_for_piotr_is_kept(db: Path) -> None:
    t = "The CEO earns 48000 PLN."
    f = FilledText(text=t, spans=[Span(0, 14, "model"), Span(14, 19, "gateway", "{x1}"), Span(19, len(t), "model")])
    out, d = filter_output(f, PIOTR, POLICY)
    assert out == t and d.verdict == "allow"


def test_product_price_is_not_touched(db: Path) -> None:
    t = "The Laptop Pro 14 costs 7,499 PLN."
    out, d = filter_output(model_text(t), ANNA, POLICY)
    assert out == t and d.verdict == "allow"


def test_guess_split_around_an_inserted_value_is_still_caught(db: Path) -> None:
    t = "48000"
    f = FilledText(text=t, spans=[Span(0, 2, "gateway", "{x1}"), Span(2, 5, "model")])
    out, _ = filter_output(f, ANNA, POLICY)
    assert CEO_SALARY not in out


def test_block_mode_blocks_the_answer(db: Path) -> None:
    out, d = filter_output(model_text("It is 48000."), ANNA, _policy(mode="block"))
    assert out == "" and d.verdict == "block"


def test_disabled_index_leaves_numbers_alone(db: Path) -> None:
    t = "It is 48000."
    out, _ = filter_output(model_text(t), ANNA, _policy(protected_values={"enabled": False, "min_digits": 4}))
    assert out == t


def test_unavailable_index_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACL_DB_PATH", str(tmp_path / "missing.db"))
    out, d = filter_output(model_text("Hello."), ANNA, POLICY)
    assert out == "" and d.verdict == "block"


def test_index_values_never_appear_in_repr_or_reasons(db: Path) -> None:
    _, d = filter_output(model_text("It is 48000."), ANNA, POLICY)
    assert CEO_SALARY not in repr(d)
    assert CEO_SALARY not in repr(protected_index._STORE)


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


@pytest.fixture
def real_chain(db: Path, fake_steps: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    for name, fn in {"validate_sql": validate_sql, "authorize": authorize, "execute": execute,
                     "disclose": disclose}.items():
        monkeypatch.setattr(loop, name, fn)


def _ask(client: TestClient, key: str) -> str:
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer " + key},
                    json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "What does the CEO earn?"}]})
    return r.json()["choices"][0]["message"]["content"]


def test_anna_answer_with_a_guessed_ceo_salary_is_redacted(client: TestClient, stub: StubModel, real_chain: None) -> None:
    stub.add(text("The CEO earns 48,000 PLN; a laptop costs 7499 PLN."))
    assert _ask(client, "demo-anna") == "The CEO earns " + REDACTED + " PLN; a laptop costs 7499 PLN."


def test_piotr_gets_the_ceo_salary_the_gateway_inserted(client: TestClient, stub: StubModel, real_chain: None) -> None:
    stub.add(tool_call("query_data", {"sql": "SELECT salary FROM salaries WHERE employee_id = 'katarzyna'",
                                      "purpose": "ceo salary", "expect": "scalar"}),
             text("The CEO earns {x1} PLN."))
    assert _ask(client, "demo-piotr") == "The CEO earns 48000 PLN."


def test_value_glued_to_a_three_digit_group_is_still_caught() -> None:
    t = "It is 48000 100 or 48,000,100."
    assert [t[s:e] for s, e in find_protected(t, frozenset({CEO_SALARY}), 4)] == ["48000 100", "48,000,100"]


# ---------------------------------------------------------------------------
# The executor's index read (only executor.py opens the database, I1)
# ---------------------------------------------------------------------------


def test_index_read_returns_only_the_requested_columns(db: Path) -> None:
    from gateway.binding.executor import read_column_values

    out = read_column_values({("salaries", "salary")})
    assert list(out) == [("salaries", "salary")] and 48000 in out[("salaries", "salary")]


@pytest.mark.parametrize("column", [("salaries", "bonus"), ("secrets", "x"), ('salaries"; DROP', "salary")])
def test_index_read_refuses_unknown_tables_and_columns(db: Path, column: tuple[str, str]) -> None:
    from gateway.binding.executor import read_column_values

    with pytest.raises(ValueError):
        read_column_values({column})
