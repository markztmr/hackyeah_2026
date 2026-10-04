"""Empty model answers (spec section 8 'Model and tool loop stage').

A small model sometimes replies with nothing: no text and no tool call. The tool loop asks
once more (budget-checked, inside max_tool_iterations); if the answer is still empty, the
gateway sends a fixed notice instead of a blank message, so a turn never looks lost.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway.llm.client import StubModel, text, tool_call
from gateway.pipeline import EMPTY_ANSWER

ANNA = {"Authorization": "Bearer demo-anna"}
TICKET = {"type": "function", "function": {"name": "create_ticket"}}


def _ask(client: TestClient, key: str = "demo-anna", **body: Any) -> Any:
    return client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {key}"},
                       json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "Hi"}], **body})


def _content(r: Any) -> str:
    return r.json()["choices"][0]["message"]["content"]


def test_an_empty_answer_is_retried_once_and_the_retry_wins(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(text(""), text("Hello."))
    r = _ask(client)
    assert _content(r) == "Hello." and r.headers["x-acl-verdict"] == "allow"
    assert len(stub.calls) == 2
    assert stub.calls[0].messages == stub.calls[1].messages  # the same question, asked again


@pytest.mark.parametrize("blank", ["", "   \n\t "])
def test_still_empty_after_the_retry_gives_the_user_a_notice(
    client: TestClient, stub: StubModel, fake_steps, audit_records: Callable[[], list[dict[str, Any]]], blank: str,
) -> None:
    stub.add(text(blank), text(blank))
    r = _ask(client)
    assert _content(r) == EMPTY_ANSWER and r.headers["x-acl-verdict"] == "allow"
    assert len(stub.calls) == 2  # one retry, never more
    (record,) = audit_records()
    notes = [d["reason"] for d in record["decisions"] if d["control"] == "models.answer"]
    assert notes == ["The model returned an empty answer; asked once more.", "The model returned an empty answer."]


def test_a_tool_call_with_no_text_is_a_normal_turn(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(tool_call("create_ticket", {"title": "Printer"}))
    r = _ask(client, "demo-piotr", tools=[TICKET])
    message = r.json()["choices"][0]["message"]
    assert [c["function"]["name"] for c in message["tool_calls"]] == ["create_ticket"]
    assert message["content"] == "" and len(stub.calls) == 1  # no retry, no notice


def test_streaming_clients_get_the_notice_too(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(text(""), text(""))
    r = _ask(client, stream=True)
    first = json.loads(r.text.split("\n\n")[0].removeprefix("data: "))
    assert first["choices"][0]["delta"]["content"] == EMPTY_ANSWER


def test_the_retry_is_budget_checked_like_any_model_call(
    client: TestClient, stub: StubModel, fake_steps, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gateway.agency import loop
    from gateway.models import Decision

    checks: list[int] = []
    real = loop.check_model_and_budget

    def second_call_over_budget(p, m, e, pol):  # noqa: ANN001, ANN202
        checks.append(e)
        if len(checks) == 2:
            return Decision("model_and_budget", "budgets.tokens_per_day", "block", "Daily token budget is exhausted.")
        return real(p, m, e, pol)

    monkeypatch.setattr(loop, "check_model_and_budget", second_call_over_budget)
    stub.add(text(""), text("never asked"))
    r = _ask(client)
    assert r.headers["x-acl-verdict"] == "block" and "budget" in _content(r)
    assert len(stub.calls) == 1 and len(checks) == 2


def test_the_retry_stays_inside_the_iteration_limit(db) -> None:  # noqa: ANN001 - fixture
    from pathlib import Path

    from gateway.agency import loop
    from gateway.models import Principal, SanitizedRequest, Vault
    from gateway.policy.loader import load_policy, setting

    policy = load_policy(Path(__file__).resolve().parent.parent / "policy.yaml")
    iterations = int(setting(policy, "tool_controls.max_tool_iterations"))
    query = {"sql": "SELECT salary FROM salaries WHERE employee_id = :current_user", "purpose": "t", "expect": "scalar"}
    stub = StubModel(fallback=tool_call("query_data", query))
    stub.add(text(""))  # empty first, then a model that never stops querying
    req = SanitizedRequest(messages=[{"role": "user", "content": "q"}], tools=[])
    loop.run_tool_loop(req, Principal("anna", "intern", "sales", "deny"), Vault(), policy,
                       models=lambda purpose, pol: stub)
    assert len(stub.calls) <= iterations + 1 and stub.calls[-1].tools is None


def test_the_demo_agent_shows_an_empty_answer_instead_of_skipping_it() -> None:
    from pathlib import Path

    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(Path(__file__).resolve().parent.parent / "demo_agent" / "app.py"), default_timeout=20)
    at.session_state["histories"] = {"anna": [
        {"role": "user", "content": "Hi"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "send_email", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "Email queued."},
        {"role": "assistant", "content": ""},
    ]}
    at.run()
    assert not at.exception
    notes = [c.value for c in at.caption if "empty answer" in c.value]
    assert notes == ["(empty answer from the gateway)"]  # the final answer shows; the tool-call round does not
