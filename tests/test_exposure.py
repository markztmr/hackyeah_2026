"""Hidden values never reach a model, in this request or later ones. Spec section 4 example D, I7, I9.

Owner: Person 4. Two turns through the HTTP endpoint with the same pipeline as
``test_e2e.py``: everything real except the models (scripted stubs).
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway.llm.client import StubModel, text, tool_call
from tests.test_e2e import ANNA_SALARY, ANSWER_A, CEO_SALARY, QUESTION_A, answer, ask, example_a, forms

FIRST_ANSWER = "Your salary is 6200 PLN."


def _inputs_since(stub: StubModel, first_call: int) -> str:
    return "\n".join(str(m) for c in stub.calls[first_call:] for m in c.messages)


def _turn_one(client: TestClient, stub: StubModel, key: str = "demo-anna") -> list[dict[str, Any]]:
    """Anna asks for her salary; the gateway fills it. Returns the history her client keeps."""
    stub.add(tool_call("query_data", {"sql": "SELECT salary FROM salaries WHERE employee_id = :current_user",
                                      "purpose": "own salary", "expect": "scalar"}),
             text("Your salary is {x1} PLN."))
    question = {"role": "user", "content": "What is my salary?"}
    r = ask(client, key, [question])
    assert answer(r) == FIRST_ANSWER
    return [question, {"role": "assistant", "content": answer(r)}]


def test_worked_example_d_history_from_a_reaches_the_model_as_prior_value(
    client: TestClient, stub: StubModel, judge_stub: StubModel, db: Path,
    all_model_inputs: Callable[..., str],
) -> None:
    """D. Anna's client sends turn A back as history; 6200 becomes [PRIOR_VALUE] before any model sees it."""
    first = answer(example_a(client, stub))
    assert first == ANSWER_A

    turn_two = len(stub.calls)
    stub.add(text("Yes, that is above the company median."))
    history = [{"role": "user", "content": QUESTION_A}, {"role": "assistant", "content": first},
               {"role": "user", "content": "Is my salary above average?"}]
    r = ask(client, "demo-anna", history)
    assert r.status_code == 200 and r.headers["x-acl-verdict"] == "allow"

    sent = _inputs_since(stub, turn_two)
    assert "Your salary is [PRIOR_VALUE] PLN. The CEO earns [UNAVAILABLE] PLN." in sent
    everything = all_model_inputs(stub, judge_stub)  # both turns, answer model and judge
    for value in (ANNA_SALARY, CEO_SALARY):
        assert not any(f in everything for f in forms(value)), value


def test_salary_never_reaches_the_model_in_deny_mode(
    client: TestClient, stub: StubModel, judge_stub: StubModel, db: Path,
    all_model_inputs: Callable[..., str],
) -> None:
    _turn_one(client, stub)
    assert not any(f in all_model_inputs(stub, judge_stub) for f in forms(ANNA_SALARY))


def test_another_users_history_is_not_remasked(client: TestClient, stub: StubModel, db: Path) -> None:
    _turn_one(client, stub, "demo-anna")
    start = len(stub.calls)
    stub.add(text("Noted."))
    ask(client, "demo-marek", [{"role": "user", "content": "Hi"},
                               {"role": "assistant", "content": "Order 6200 shipped."},
                               {"role": "user", "content": "Thanks"}])
    sent = _inputs_since(stub, start)
    assert "Order 6200 shipped." in sent and "[PRIOR_VALUE]" not in sent


def test_issued_value_expires_after_the_ttl(
    client: TestClient, stub: StubModel, db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.inbound import history

    now = [1_000_000.0]
    monkeypatch.setattr(history, "_now", lambda: now[0])
    past = _turn_one(client, stub)
    now[0] += 60 * 60 + 1  # policy.yaml history_remask.ttl_minutes: 60
    start = len(stub.calls)
    stub.add(text("Ok."))
    ask(client, "demo-anna", [*past, {"role": "user", "content": "Thanks"}])
    assert FIRST_ANSWER in _inputs_since(stub, start)  # expired: the user's own old text is no longer masked
