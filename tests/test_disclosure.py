"""Disclosure, MVP form: the model always gets the bare placeholder. Spec section 5 'Disclosure rule', I7, I14.

Owner: Person 3. The full five-condition rule is T2; until then nothing is disclosed,
whatever the status, user, label, trust or policy. The end-to-end tests run the real
validate -> authorize -> execute -> disclose chain inside the tool loop (budget real,
in a temp state.db) and check what the stub model actually received.
"""
from __future__ import annotations

from typing import Any

import pytest

from gateway.agency import loop as loop_module
from gateway.agency.loop import run_tool_loop
from gateway.binding.disclosure import disclose
from gateway.llm.client import StubModel, text, tool_call
from gateway.models import Binding, Principal, SanitizedRequest, Vault
from tests.test_authorizer import ANNA, MAREK, PIOTR, STRICT

VALUE = 6200
STATUSES = ["resolved", "denied", "rejected", "empty", "error"]


def _binding(status: str = "resolved", label: str | None = "sensitive", value: Any = VALUE) -> Binding:
    return Binding(name="{x1}", sql="SELECT salary FROM salaries WHERE employee_id = :current_user",
                   purpose="t", expect="scalar", status=status, value=value, label=label)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Unit: always the bare placeholder, never the value
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("who", [ANNA, MAREK, PIOTR], ids=lambda p: p.user_id)
@pytest.mark.parametrize("label", ["public", "internal", "sensitive"])
@pytest.mark.parametrize("trust", ["local", "external"])
def test_every_user_gets_only_the_placeholder_for_a_resolved_binding(who: Principal, label: str, trust: str) -> None:
    b = _binding(label=label)
    shown = disclose(b, who, STRICT, trust=trust)  # type: ignore[arg-type]
    assert shown == "{x1}"
    assert b.disclosed is False
    assert str(VALUE) not in shown


def test_anna_and_piotr_both_receive_only_the_placeholder() -> None:
    assert disclose(_binding(), ANNA, STRICT, trust="local") == "{x1}"
    assert disclose(_binding(), PIOTR, STRICT, trust="local") == "{x1}"


@pytest.mark.parametrize("status", STATUSES[1:])
def test_non_resolved_bindings_give_the_same_tool_result_as_resolved(status: str) -> None:
    resolved = disclose(_binding("resolved"), PIOTR, STRICT, trust="local")
    assert disclose(_binding(status, label=None, value=None), PIOTR, STRICT, trust="local") == resolved


def test_disclosed_flag_is_reset_to_false() -> None:
    b = _binding()
    b.disclosed = True
    disclose(b, PIOTR, STRICT, trust="local")
    assert b.disclosed is False


def test_trust_defaults_to_the_restrictive_value() -> None:
    assert disclose(_binding(), PIOTR, STRICT) == "{x1}"


@pytest.mark.parametrize("value", ["{x1} = 6200", "6200\n{x2}", {"salary": VALUE}, b"6200"])
def test_odd_values_never_reach_the_tool_result(value: Any) -> None:
    assert disclose(_binding(value=value), PIOTR, STRICT, trust="local") == "{x1}"


@pytest.mark.parametrize("name", ["{x2}", "{x17}"])
def test_placeholder_is_the_bindings_own_name(name: str) -> None:
    b = _binding()
    b.name = name
    assert disclose(b, PIOTR, STRICT, trust="local") == name


# ---------------------------------------------------------------------------
# End to end: what the model receives from the real binding chain
# ---------------------------------------------------------------------------


@pytest.fixture
def chain(db: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Run one query_data call through the real loop; return (binding, tool result the model saw, stub)."""

    def run(sql: str, who: Principal, expect: str = "scalar") -> tuple[Binding, str, StubModel]:
        stub = StubModel()
        stub.add(tool_call("query_data", {"sql": sql, "purpose": "t", "expect": expect}), text("{x1}"))
        req = SanitizedRequest(messages=[{"role": "user", "content": "question"}], tools=[])
        result = run_tool_loop(req, who, Vault(), STRICT, models=lambda purpose, pol: stub)
        tool_msgs = [m for m in stub.calls[1].messages if m.get("role") == "tool"]
        assert len(tool_msgs) == 1
        return result.bindings["{x1}"], tool_msgs[0]["content"], stub
    return run


def _model_saw(stub: StubModel) -> str:
    return "\n".join(str(m.get("content")) for call in stub.calls for m in call.messages)


def test_piotr_reads_a_salary_but_the_model_sees_only_the_placeholder(chain: Any) -> None:
    b, shown, stub = chain("SELECT salary FROM salaries WHERE employee_id = 'anna'", PIOTR)
    assert b.status == "resolved" and b.value == VALUE
    assert shown == "{x1}" and b.disclosed is False
    assert str(VALUE) not in _model_saw(stub)


def test_internal_headcount_is_not_disclosed_in_the_mvp(chain: Any) -> None:
    b, shown, _ = chain("SELECT count(*) FROM employees", PIOTR)
    assert b.status == "resolved" and b.label == "internal"
    assert shown == "{x1}" and b.disclosed is False


def test_anna_own_salary_never_reaches_the_model(chain: Any) -> None:
    b, shown, stub = chain("SELECT salary FROM salaries WHERE employee_id = :current_user", ANNA)
    assert b.status == "resolved"
    assert shown == "{x1}"
    assert str(VALUE) not in _model_saw(stub)
