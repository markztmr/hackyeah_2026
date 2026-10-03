"""Hidden values never reach a model, in this request or later ones. Spec section 4 example D, I9.

Owner: Person 4. Two turns through the HTTP endpoint with the real binding chain,
disclosure, fill, issued-value recording and history re-masking. The rest of inbound
and the judge are still the ``fake_steps`` stand-ins.
"""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway.agency import loop
from gateway.binding.authorizer import authorize
from gateway.binding.disclosure import disclose
from gateway.binding.executor import execute
from gateway.binding.sql_validator import validate_sql
from gateway.llm.client import StubModel, text, tool_call

SALARY_FORMS = ("6200", "6,200", "6 200", "6.200")
FIRST_ANSWER = "Your salary is 6200 PLN."


@pytest.fixture
def real_chain(db: Any, fake_steps: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loop, "validate_sql", validate_sql)
    monkeypatch.setattr(loop, "authorize", authorize)
    monkeypatch.setattr(loop, "execute", execute)
    monkeypatch.setattr(loop, "disclose", disclose)


def _post(client: TestClient, key: str, messages: list[dict[str, Any]]) -> Any:
    return client.post("/v1/chat/completions", headers={"Authorization": "Bearer " + key},
                       json={"model": "qwen2.5:3b", "messages": messages})


def _model_input(stub: StubModel, first_call: int = 0) -> str:
    return "\n".join(str(m) for c in stub.calls[first_call:] for m in c.messages)


def _turn_one(client: TestClient, stub: StubModel, key: str = "demo-anna") -> list[dict[str, Any]]:
    """Anna asks for her salary; the gateway fills it. Returns the history her client keeps."""
    stub.add(tool_call("query_data", {"sql": "SELECT salary FROM salaries WHERE employee_id = :current_user",
                                      "purpose": "own salary", "expect": "scalar"}),
             text("Your salary is {x1} PLN."))
    question = {"role": "user", "content": "What is my salary?"}
    r = _post(client, key, [question])
    answer = r.json()["choices"][0]["message"]["content"]
    assert answer == FIRST_ANSWER
    return [question, {"role": "assistant", "content": answer}]


def test_turn_two_history_reaches_the_model_as_prior_value(
    client: TestClient, stub: StubModel, real_chain: None
) -> None:
    """Worked example D."""
    history = _turn_one(client, stub)
    assert not any(f in _model_input(stub) for f in SALARY_FORMS)  # turn 1: placeholder only

    turn_two_starts = len(stub.calls)
    stub.add(text("I can help with that."))
    r = _post(client, "demo-anna", [*history, {"role": "user", "content": "Is that above average?"}])
    assert r.status_code == 200 and r.headers["x-acl-verdict"] == "allow"

    sent = _model_input(stub, turn_two_starts)
    assert "Your salary is [PRIOR_VALUE] PLN." in sent
    assert not any(f in sent for f in SALARY_FORMS)


def test_another_users_history_is_not_remasked(client: TestClient, stub: StubModel, real_chain: None) -> None:
    _turn_one(client, stub, "demo-anna")
    start = len(stub.calls)
    stub.add(text("Noted."))
    _post(client, "demo-marek", [{"role": "user", "content": "Hi"},
                                 {"role": "assistant", "content": "Order 6200 shipped."},
                                 {"role": "user", "content": "Thanks"}])
    sent = _model_input(stub, start)
    assert "Order 6200 shipped." in sent and "[PRIOR_VALUE]" not in sent


def test_issued_value_expires_after_the_ttl(
    client: TestClient, stub: StubModel, real_chain: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.inbound import history

    now = [1_000_000.0]
    monkeypatch.setattr(history, "_now", lambda: now[0])
    past = _turn_one(client, stub)
    now[0] += 60 * 60 + 1  # policy.yaml history_remask.ttl_minutes: 60
    start = len(stub.calls)
    stub.add(text("Ok."))
    _post(client, "demo-anna", [*past, {"role": "user", "content": "Thanks"}])
    assert FIRST_ANSWER in _model_input(stub, start)  # expired: the user's own old text is no longer masked
