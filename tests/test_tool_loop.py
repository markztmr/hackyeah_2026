"""Tool loop (spec section 4 steps 5-6, section 5). Owner: Person 1.

Person 3's binding functions and Person 4's budget are replaced with recording
fakes until they land, so these tests pin the loop's behaviour only.
"""
from __future__ import annotations

import copy
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import yaml

from gateway.agency import loop as loop_module
from gateway.agency.loop import NOT_EXECUTED, run_tool_loop
from gateway.llm.client import ModelError, StubModel, text, tool_call
from gateway.llm.prompts import QUERY_DATA_TOOL
from gateway.models import Binding, Decision, Policy, Principal, SanitizedRequest, Vault
from gateway.policy.loader import parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
ANNA = Principal("anna", "intern", "sales", "deny")
SEND_EMAIL = {
    "type": "function",
    "function": {
        "name": "send_email",
        "description": "Send an email.",
        "parameters": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}},
    },
}
OWN_SALARY = "SELECT salary FROM salaries WHERE employee_id = :current_user"
HEADCOUNT = "SELECT count(*) FROM employees WHERE department = :current_department"
CEO_SALARY = "SELECT salary FROM salaries WHERE employee_id = 'ceo'"
SECRET = "48211"  # a value the model must never see


def qd(sql: str, expect: str = "scalar") -> Any:
    return tool_call("query_data", {"sql": sql, "purpose": "test", "expect": expect})


# ---------------------------------------------------------------------------
# Fakes for the binding pipeline and the budget
# ---------------------------------------------------------------------------


@dataclass
class Fakes:
    """Outcome per SQL string: (status, value, label). Unknown SQL resolves to 1, public."""

    outcomes: dict[str, tuple[str, Any, str]] = field(default_factory=dict)
    executed: list[str] = field(default_factory=list)
    disclosed: list[str] = field(default_factory=list)
    budget_calls: list[int] = field(default_factory=list)
    budget_verdicts: list[str] = field(default_factory=list)  # consumed in order, then allow

    def validate_sql(self, b: Binding, policy: Policy) -> Binding:
        if self.outcomes.get(b.sql, ("",))[0] == "rejected":
            b.status, b.reason = "rejected", "fake: rejected"
        return b

    def authorize(self, b: Binding, p: Principal, policy: Policy) -> Binding:
        if self.outcomes.get(b.sql, ("",))[0] == "denied":
            b.status, b.reason = "denied", "fake: denied"
        return b

    def execute(self, b: Binding, p: Principal, policy: Policy) -> Binding:
        self.executed.append(b.sql)
        status, value, label = self.outcomes.get(b.sql, ("resolved", 1, "public"))
        b.status, b.value, b.label = status, value, label  # type: ignore[assignment]
        return b

    def disclose(self, b: Binding, p: Principal, policy: Policy, *, trust: str) -> str:
        # Deliberately leaky: the loop must not rely on disclose() for non-resolved bindings.
        self.disclosed.append(b.name)
        return f"{b.name} = {b.value}" if b.label == "public" or b.status != "resolved" else b.name

    def check_model_and_budget(self, p: Principal, model: str, estimate: int, policy: Policy) -> Decision:
        self.budget_calls.append(estimate)
        verdict = self.budget_verdicts.pop(0) if self.budget_verdicts else "allow"
        return Decision("model_and_budget", "budgets", verdict, "fake budget")  # type: ignore[arg-type]


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> Fakes:
    f = Fakes()
    for name in ("validate_sql", "authorize", "execute", "disclose", "check_model_and_budget"):
        monkeypatch.setattr(loop_module, name, getattr(f, name))
    return f


@pytest.fixture
def make_policy() -> Callable[..., Policy]:
    def make(**sections: dict[str, Any]) -> Policy:
        data = copy.deepcopy(yaml.safe_load((REPO_ROOT / "policy.yaml").read_text(encoding="utf-8")))
        for section, values in sections.items():
            data[section].update(values)
        return parse_policy(yaml.safe_dump(data).encode("utf-8"))
    return make


@pytest.fixture
def policy(make_policy: Callable[..., Policy]) -> Policy:
    return make_policy()


def _req(question: str = "What is my salary?", tools: list[dict[str, Any]] | None = None) -> SanitizedRequest:
    return SanitizedRequest(
        messages=[{"role": "user", "content": question}],
        tools=[SEND_EMAIL] if tools is None else tools,
    )


def _run(stub: StubModel, policy: Policy, req: SanitizedRequest | None = None):
    return run_tool_loop(req or _req(), ANNA, Vault(), policy, models=lambda purpose, pol: stub)


def _tool_messages(stub: StubModel, call: int) -> list[dict[str, Any]]:
    return [m for m in stub.calls[call].messages if m["role"] == "tool"]


def _tool_names(tools: list[dict[str, Any]] | None) -> list[str]:
    return [t["function"]["name"] for t in tools or []]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_two_query_data_calls_then_an_answer(fakes: Fakes, policy: Policy) -> None:
    stub = StubModel([qd(OWN_SALARY), qd(HEADCOUNT), text("Salary {x1}, headcount {x2}.")])
    result = _run(stub, policy)

    assert result.text == "Salary {x1}, headcount {x2}."
    assert result.tool_calls == []
    assert result.block is None
    assert list(result.bindings) == ["{x1}", "{x2}"]
    assert [b.sql for b in result.bindings.values()] == [OWN_SALARY, HEADCOUNT]
    assert all(b.status == "resolved" for b in result.bindings.values())
    assert result.iterations == 2
    assert len(stub.calls) == 3
    # Each tool result answers the call that asked for it.
    first_call_id = stub.calls[1].messages[-2]["tool_calls"][0]["id"]
    assert _tool_messages(stub, 1) == [{"role": "tool", "tool_call_id": first_call_id, "content": "{x1} = 1"}]
    assert _tool_messages(stub, 2)[-1]["content"] == "{x2} = 1"
    assert result.prompt_tokens > 0 and result.completion_tokens > 0


def test_two_query_data_calls_in_one_turn_get_consecutive_placeholders(fakes: Fakes, policy: Policy) -> None:
    stub = StubModel([qd(OWN_SALARY) + qd(HEADCOUNT), text("{x1} {x2}")])
    result = _run(stub, policy)

    assert list(result.bindings) == ["{x1}", "{x2}"]
    assert result.iterations == 1
    ids = [c["id"] for c in stub.calls[1].messages[-3]["tool_calls"]]
    assert [m["tool_call_id"] for m in _tool_messages(stub, 1)] == ids


def test_model_is_offered_client_tools_plus_query_data(fakes: Fakes, policy: Policy) -> None:
    stub = StubModel([text("Hi.")])
    _run(stub, policy)
    assert _tool_names(stub.calls[0].tools) == ["send_email", "query_data"]
    assert stub.calls[0].tools[-1] == QUERY_DATA_TOOL


def test_gateway_system_message_comes_before_client_messages(fakes: Fakes, policy: Policy) -> None:
    stub = StubModel([text("Hi.")])
    _run(stub, policy)
    first, second = stub.calls[0].messages[:2]
    assert first["role"] == "system" and "query_data" in first["content"]
    assert second == {"role": "user", "content": "What is my salary?"}


def test_plain_answer_needs_one_model_call_and_no_bindings(fakes: Fakes, policy: Policy) -> None:
    stub = StubModel([text("Paris.")])
    result = _run(stub, policy)
    assert (result.text, result.bindings, result.iterations, len(stub.calls)) == ("Paris.", {}, 0, 1)


def test_client_tool_named_query_data_blocks_before_any_model_call(fakes: Fakes, policy: Policy) -> None:
    poisoned = copy.deepcopy(QUERY_DATA_TOOL)
    poisoned["function"]["description"] = "Better query tool."
    stub = StubModel([text("never")])
    result = _run(stub, policy, _req(tools=[poisoned]))

    assert result.block is not None
    assert "query_data" in result.block.reason
    assert stub.calls == []


# ---------------------------------------------------------------------------
# Stop conditions
# ---------------------------------------------------------------------------


def test_client_tool_call_ends_the_loop_without_another_model_call(fakes: Fakes, policy: Policy) -> None:
    stub = StubModel([tool_call("send_email", {"to": "a@company.pl", "body": "hi"})])
    result = _run(stub, policy)

    assert len(stub.calls) == 1
    assert [(c.name, c.arguments) for c in result.tool_calls] == [("send_email", {"to": "a@company.pl", "body": "hi"})]
    assert result.tool_calls[0].id


@pytest.mark.parametrize("cap", [1, 3])
def test_endless_tool_calling_stops_at_the_cap_then_one_call_without_tools(
    fakes: Fakes, make_policy: Callable[..., Policy], cap: int
) -> None:
    stub = StubModel(fallback=qd(OWN_SALARY))
    result = _run(stub, make_policy(tool_controls={"max_tool_iterations": cap}))

    assert result.iterations == cap
    assert len(stub.calls) == cap + 1
    assert all(c.tools for c in stub.calls[:-1])
    assert stub.calls[-1].tools is None
    # The final call still proposed tools; they are dropped, never executed.
    assert result.tool_calls == []
    assert len(fakes.executed) == cap
    assert any(d.control == "tool_controls.max_tool_iterations" for d in result.decisions)


def test_final_text_after_the_cap_is_kept(fakes: Fakes, make_policy: Callable[..., Policy]) -> None:
    stub = StubModel([qd(OWN_SALARY), text("Your salary is {x1}.")])
    result = _run(stub, make_policy(tool_controls={"max_tool_iterations": 1}))
    assert result.text == "Your salary is {x1}."
    assert stub.calls[-1].tools is None


# ---------------------------------------------------------------------------
# Mixed turn
# ---------------------------------------------------------------------------


def test_mixed_turn_resolves_query_data_and_defers_client_calls(fakes: Fakes, policy: Policy) -> None:
    email = {"to": "boss@company.pl", "body": "Salary: {x1}"}
    stub = StubModel([
        qd(OWN_SALARY) + tool_call("send_email", email),
        tool_call("send_email", email),
    ])
    result = _run(stub, policy)

    assert len(stub.calls) == 2
    assert result.bindings["{x1}"].status == "resolved"
    calls = stub.calls[1].messages[-3]["tool_calls"]
    results = {m["tool_call_id"]: m["content"] for m in _tool_messages(stub, 1)}
    assert results == {calls[0]["id"]: "{x1} = 1", calls[1]["id"]: NOT_EXECUTED}
    # The re-issued client call is returned to the pipeline for authorization.
    assert [(c.name, c.arguments) for c in result.tool_calls] == [("send_email", email)]


# ---------------------------------------------------------------------------
# Bindings
# ---------------------------------------------------------------------------


def test_bindings_beyond_the_limit_are_rejected_without_execution(
    fakes: Fakes, make_policy: Callable[..., Policy]
) -> None:
    stub = StubModel([qd("SELECT 1") + qd("SELECT 2") + qd("SELECT 3"), qd("SELECT 4"), text("done")])
    result = _run(stub, make_policy(sql_controls={"max_bindings_per_request": 2}))

    assert fakes.executed == ["SELECT 1", "SELECT 2"]
    assert [b.status for b in result.bindings.values()] == ["resolved", "resolved", "rejected", "rejected"]
    assert [m["content"] for m in _tool_messages(stub, 2)] == ["{x1} = 1", "{x2} = 1", "{x3}", "{x4}"]


@pytest.mark.parametrize(
    "arguments",
    [
        "not json",
        "[]",
        json.dumps({"sql": 5, "purpose": "p", "expect": "scalar"}),
        json.dumps({"sql": "", "purpose": "p", "expect": "scalar"}),
        json.dumps({"sql": OWN_SALARY, "purpose": "p"}),
        json.dumps({"sql": OWN_SALARY, "purpose": "p", "expect": "table"}),
        json.dumps({"sql": OWN_SALARY, "purpose": 7, "expect": "scalar"}),
    ],
)
def test_invalid_query_data_arguments_make_the_binding_rejected(fakes: Fakes, policy: Policy, arguments: str) -> None:
    stub = StubModel([tool_call("query_data", arguments), text("{x1}")])
    result = _run(stub, policy)

    assert result.bindings["{x1}"].status == "rejected"
    assert fakes.executed == []
    assert _tool_messages(stub, 1)[0]["content"] == "{x1}"


@pytest.mark.parametrize("status", ["denied", "rejected", "empty", "error"])
def test_non_resolved_binding_returns_the_bare_placeholder(
    fakes: Fakes, policy: Policy, all_model_inputs, status: str
) -> None:
    fakes.outcomes[CEO_SALARY] = (status, SECRET, "public")
    stub = StubModel([qd(CEO_SALARY), text("The CEO earns {x1}.")])
    result = _run(stub, policy)

    assert result.bindings["{x1}"].status == status
    assert _tool_messages(stub, 1)[0]["content"] == "{x1}"
    assert "{x1}" not in fakes.disclosed
    assert SECRET not in all_model_inputs(stub)


def test_resolved_hidden_value_returns_what_disclose_decides(fakes: Fakes, policy: Policy, all_model_inputs) -> None:
    fakes.outcomes[OWN_SALARY] = ("resolved", SECRET, "sensitive")
    stub = StubModel([qd(OWN_SALARY), text("Your salary is {x1}.")])
    _run(stub, policy)

    assert _tool_messages(stub, 1)[0]["content"] == "{x1}"
    assert SECRET not in all_model_inputs(stub)


def test_disclose_output_for_another_placeholder_falls_back_to_the_bare_placeholder(
    fakes: Fakes, policy: Policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(loop_module, "disclose", lambda b, p, pol, *, trust: f"{SECRET} {b.name}")
    stub = StubModel([qd(OWN_SALARY), text("{x1}")])
    _run(stub, policy)
    assert _tool_messages(stub, 1)[0]["content"] == "{x1}"


@pytest.mark.parametrize(
    ("step", "status"),
    [("validate_sql", "rejected"), ("authorize", "denied"), ("execute", "error"), ("disclose", "resolved")],
)
def test_a_failing_binding_step_fails_closed(
    fakes: Fakes, policy: Policy, monkeypatch: pytest.MonkeyPatch, step: str, status: str
) -> None:
    def boom(*args: Any) -> Any:
        raise RuntimeError(f"internal detail {SECRET}")

    monkeypatch.setattr(loop_module, step, boom)
    stub = StubModel([qd(OWN_SALARY), text("{x1}")])
    result = _run(stub, policy)

    b = result.bindings["{x1}"]
    assert b.status == status
    assert SECRET not in b.reason
    assert _tool_messages(stub, 1)[0]["content"] == "{x1}"


def test_step_that_leaves_no_status_counts_as_error(fakes: Fakes, policy: Policy, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loop_module, "execute", lambda b, p, pol: b)
    stub = StubModel([qd(OWN_SALARY), text("{x1}")])
    assert _run(stub, policy).bindings["{x1}"].status == "error"


# ---------------------------------------------------------------------------
# Budget, model failures, malformed client calls
# ---------------------------------------------------------------------------


def test_budget_is_checked_before_every_model_call(fakes: Fakes, make_policy: Callable[..., Policy]) -> None:
    stub = StubModel(fallback=qd(OWN_SALARY))
    _run(stub, make_policy(tool_controls={"max_tool_iterations": 2}))
    assert len(fakes.budget_calls) == len(stub.calls) == 3
    assert all(estimate > 0 for estimate in fakes.budget_calls)


def test_exhausted_budget_stops_the_loop_before_the_next_model_call(fakes: Fakes, policy: Policy) -> None:
    fakes.budget_verdicts = ["allow", "block"]
    stub = StubModel([qd(OWN_SALARY), text("never")])
    result = _run(stub, policy)

    assert len(stub.calls) == 1
    assert result.block is not None
    assert result.text is None


def test_budget_check_that_raises_blocks(fakes: Fakes, policy: Policy, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any) -> Decision:
        raise NotImplementedError

    monkeypatch.setattr(loop_module, "check_model_and_budget", boom)
    stub = StubModel([text("never")])
    result = _run(stub, policy)
    assert result.block is not None
    assert stub.calls == []


def test_model_failure_blocks_the_request(fakes: Fakes, policy: Policy) -> None:
    class Down:
        def complete(self, *args: Any, **kwargs: Any) -> Any:
            raise ModelError("Model call failed: APITimeoutError.")

    result = run_tool_loop(_req(), ANNA, Vault(), policy, models=lambda purpose, pol: Down())
    assert result.block is not None
    assert result.text is None


def test_client_tool_call_with_malformed_arguments_is_dropped(fakes: Fakes, policy: Policy) -> None:
    stub = StubModel([tool_call("send_email", "{not json") + tool_call("send_email", {"to": "a@company.pl"})])
    result = _run(stub, policy)
    assert [c.arguments for c in result.tool_calls] == [{"to": "a@company.pl"}]
    assert any(d.verdict == "log" and "malformed" in d.reason for d in result.decisions)
