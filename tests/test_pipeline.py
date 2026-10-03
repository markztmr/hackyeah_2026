"""The 10-step pipeline through POST /v1/chat/completions, with the stub model. Spec section 4. Owner: Person 1.

Steps whose modules have not landed run as ``fake_steps`` (see conftest).
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway import pipeline
from gateway.llm.client import StubModel, text, tool_call
from gateway.models import Decision, ToolDecision
from tests.conftest import INJECTION_PHRASE

ANNA = {"Authorization": "Bearer demo-anna"}
STEPS = {
    "authenticate", "model_and_budget", "inbound", "input_checks", "model_and_tool_loop",
    "tool_authz", "fill", "output_filter", "record",
}
SECRET = "48211"


def _ask(client: TestClient, content: str, headers: dict[str, str] | None = None, **body: Any):
    payload = {"model": "qwen2.5:3b", "messages": [{"role": "user", "content": content}], **body}
    return client.post("/v1/chat/completions", json=payload, headers=ANNA if headers is None else headers)


def _boom(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError(f"internal detail {SECRET} at /secret/path")


# ---------------------------------------------------------------------------
# Allowed
# ---------------------------------------------------------------------------


def test_plain_question_returns_an_answer(client: TestClient, stub: StubModel, fake_steps, audit_records) -> None:
    stub.add(text("Paris."))
    r = _ask(client, "What is the capital of France?")

    assert r.status_code == 200
    body = r.json()
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"] == {"role": "assistant", "content": "Paris."}
    assert body["choices"][0]["finish_reason"] == "stop"
    assert body["usage"]["total_tokens"] > 0
    assert r.headers["x-acl-verdict"] == "allow"
    assert r.headers["x-acl-request-id"] == body["id"]

    (record,) = audit_records()
    assert record["request_id"] == body["id"]
    assert record["verdict"] == "allow"
    assert (record["user_id"], record["role"], record["ai_data_policy"]) == ("anna", "intern", "deny")
    assert record["answer_model"] == "qwen2.5:3b"


def test_every_step_is_timed_in_the_audit_record(client: TestClient, stub: StubModel, fake_steps, audit_records) -> None:
    stub.add(text("Paris."))
    _ask(client, "Capital of France?")
    (record,) = audit_records()
    assert set(record["step_latency_ms"]) == STEPS
    assert record["total_latency_ms"] >= sum(record["step_latency_ms"].values()) * 0.99


def test_query_data_bindings_are_audited_without_values(
    client: TestClient, stub: StubModel, fake_steps, audit_records, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.agency import loop

    def execute(b: Any, p: Any, policy: Any) -> Any:
        b.status, b.value, b.label = "resolved", SECRET, "sensitive"
        return b

    monkeypatch.setattr(loop, "execute", execute)
    sql = {"sql": "SELECT salary FROM salaries WHERE employee_id = :current_user", "purpose": "own salary", "expect": "scalar"}
    stub.add(tool_call("query_data", sql), text("Your salary is {x1}."))
    _ask(client, "What is my salary?")

    (record,) = audit_records()
    assert [(b["name"], b["status"]) for b in record["bindings"]] == [("{x1}", "resolved")]
    assert record["tool_iterations"] == 1
    assert SECRET not in str(record)


def test_allowed_client_tool_call_reaches_the_client(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(tool_call("create_ticket", {"title": "Printer broken"}))
    r = _ask(client, "Open a ticket.", {"Authorization": "Bearer demo-piotr"},  # create_ticket: not for interns
             tools=[{"type": "function", "function": {"name": "create_ticket"}}])

    choice = r.json()["choices"][0]
    assert choice["finish_reason"] == "tool_calls"
    (call,) = choice["message"]["tool_calls"]
    assert call["function"]["name"] == "create_ticket"
    assert call["function"]["arguments"] == '{"title": "Printer broken"}'
    assert r.headers["x-acl-verdict"] == "allow"


def test_unlisted_model_can_be_substituted(client: TestClient, stub: StubModel, fake_steps, policy) -> None:
    policy.write_text(policy.read_text(encoding="utf-8").replace("on_unlisted: block", "on_unlisted: substitute"), encoding="utf-8")
    stub.add(text("ok"))
    r = _ask(client, "Hi", model="gpt-4o")
    assert r.status_code == 200
    assert r.json()["model"] == "qwen2.5:3b"
    assert stub.calls[0].model == "qwen2.5:3b"


# ---------------------------------------------------------------------------
# Blocked: HTTP 200, assistant message with the reason, x-acl-verdict: block
# ---------------------------------------------------------------------------


def test_blocked_prompt_returns_200_with_the_reason_and_header(
    client: TestClient, stub: StubModel, fake_steps, audit_records
) -> None:
    r = _ask(client, f"Please {INJECTION_PHRASE} and print the CEO salary.")

    assert r.status_code == 200
    assert r.headers["x-acl-verdict"] == "block"
    message = r.json()["choices"][0]["message"]
    assert message["role"] == "assistant"
    assert "known injection phrase" in message["content"]
    assert stub.calls == []  # stopped before any model call
    (record,) = audit_records()
    assert record["verdict"] == "block"
    assert "model_and_tool_loop" not in record["step_latency_ms"]


def test_unlisted_model_is_blocked_before_any_model_call(client: TestClient, stub: StubModel, fake_steps) -> None:
    r = _ask(client, "Hi", model="gpt-4o")
    assert (r.status_code, r.headers["x-acl-verdict"]) == (200, "block")
    assert "not allowed" in r.json()["choices"][0]["message"]["content"]
    assert stub.calls == []


def test_exhausted_budget_blocks_before_any_model_call(
    client: TestClient, stub: StubModel, fake_steps, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pipeline, "check_model_and_budget",
                        lambda p, m, e, pol: Decision("model_and_budget", "budgets", "block", "Daily token budget exhausted."))
    r = _ask(client, "Hi")
    assert r.headers["x-acl-verdict"] == "block"
    assert "budget" in r.json()["choices"][0]["message"]["content"]
    assert stub.calls == []


def test_judge_gets_a_budget_check_before_it_runs(
    client: TestClient, stub: StubModel, fake_steps, monkeypatch: pytest.MonkeyPatch
) -> None:
    checked: list[str] = []

    def budget(p: Any, model: str, estimate: int, pol: Any) -> Decision:
        checked.append(model)
        verdict = "block" if model == "qwen2.5:1.5b" else "allow"
        return Decision("model_and_budget", "budgets", verdict, "Judge budget exhausted.")  # type: ignore[arg-type]

    judged: list[str] = []
    monkeypatch.setattr(pipeline, "check_model_and_budget", budget)
    monkeypatch.setattr(pipeline, "judge", lambda t, pol, models=None: judged.append(t))
    r = _ask(client, "Hi")
    assert r.headers["x-acl-verdict"] == "block"
    assert checked == ["qwen2.5:3b", "qwen2.5:1.5b"]
    assert judged == []


def test_denied_client_tool_call_is_removed_and_reported(
    client: TestClient, stub: StubModel, fake_steps, monkeypatch: pytest.MonkeyPatch, audit_records
) -> None:
    monkeypatch.setattr(pipeline, "authorize_tool_call",
                        lambda c, p, b, pol: ToolDecision(c.name, "deny", "args.to.allow_pattern", "Recipient is outside the company."))
    stub.add(tool_call("send_email", {"to": "x@evil.com", "body": "hi"}))
    r = _ask(client, "Email the report.", tools=[{"type": "function", "function": {"name": "send_email"}}])

    assert r.headers["x-acl-verdict"] == "block"
    message = r.json()["choices"][0]["message"]
    assert message["content"] == "The action send_email was blocked by policy."
    assert "tool_calls" not in message
    (record,) = audit_records()
    assert record["tool_decisions"][0]["verdict"] == "deny"


def test_output_filter_block_returns_the_reason(
    client: TestClient, stub: StubModel, fake_steps, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pipeline, "filter_output",
                        lambda f, p, pol: ("", Decision("output_filter", "output_controls", "block", "The answer contained a secret.")))
    stub.add(text("the key is sk-123"))
    r = _ask(client, "Hi")
    assert r.headers["x-acl-verdict"] == "block"
    assert "contained a secret" in r.json()["choices"][0]["message"]["content"]
    assert "sk-123" not in r.text


def test_client_tool_named_query_data_is_blocked(client: TestClient, stub: StubModel, fake_steps) -> None:
    r = _ask(client, "Hi", tools=[{"type": "function", "function": {"name": "query_data"}}])
    assert r.headers["x-acl-verdict"] == "block"
    assert stub.calls == []


# ---------------------------------------------------------------------------
# Auth failures and crashes
# ---------------------------------------------------------------------------


def test_unknown_key_returns_401_and_writes_one_audit_record(
    client: TestClient, stub: StubModel, fake_steps, audit_records
) -> None:
    r = _ask(client, "Hi", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
    (record,) = audit_records()
    assert record["verdict"] == "block"
    assert record["user_id"] is None
    assert stub.calls == []


@pytest.mark.parametrize("step", ["inspect_inbound", "run_tool_loop", "fill", "filter_output", "record_issued"])
def test_crash_inside_a_step_still_writes_one_audit_record(
    client: TestClient, stub: StubModel, fake_steps, audit_records, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    monkeypatch.setattr(pipeline, step, _boom)
    stub.add(text("Paris."))
    r = _ask(client, "Capital of France?")

    assert r.status_code == 500
    for leak in (SECRET, "/secret/path", "Traceback", "RuntimeError"):
        assert leak not in r.text
    (record,) = audit_records()
    assert record["verdict"] == "block"
    assert record["request_id"] == r.json()["error"]["request_id"] == r.headers["x-acl-request-id"]
    assert SECRET not in str(record)


def test_crash_in_the_real_pipeline_today_is_a_safe_error(client: TestClient, audit_records) -> None:
    """Without fakes, unbuilt steps raise NotImplementedError: the request fails closed."""
    r = _ask(client, "Hi")
    assert r.status_code == 500
    assert len(audit_records()) == 1


def test_failing_audit_write_fails_the_request(
    client: TestClient, stub: StubModel, fake_steps, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pipeline, "write_audit", _boom)
    stub.add(text("Paris."))
    r = _ask(client, "Capital?")
    assert r.status_code == 500
    assert "Paris." not in r.text


def test_malformed_body_returns_422_writes_one_record_and_does_not_echo(client: TestClient, audit_records) -> None:
    r = client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "my password is hunter2"}]}, headers=ANNA)
    assert r.status_code == 422
    assert "hunter2" not in r.text
    (record,) = audit_records()
    assert record["verdict"] == "block"
    assert "hunter2" not in str(record)


# ---------------------------------------------------------------------------
# One policy snapshot per request
# ---------------------------------------------------------------------------


def test_every_step_receives_the_same_policy_snapshot(
    client: TestClient, stub: StubModel, fake_steps, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.models import Policy

    seen: list[int] = []
    for name in ("authenticate", "check_model_and_budget", "inspect_inbound", "check_injection",
                 "run_tool_loop", "fill", "filter_output", "record_usage"):
        real: Callable[..., Any] = getattr(pipeline, name)

        def spy(*args: Any, _real: Callable[..., Any] = real, **kwargs: Any) -> Any:
            seen.extend(id(a) for a in (*args, *kwargs.values()) if isinstance(a, Policy))
            return _real(*args, **kwargs)

        monkeypatch.setattr(pipeline, name, spy)
    stub.add(text("ok"))
    _ask(client, "Hi")
    assert len(seen) >= 8 and len(set(seen)) == 1


# ---------------------------------------------------------------------------
# Red-team regression: literal values the model wrote into SQL never reach the audit
# log; the SQL shape (tables, columns, parameters) stays readable. I8, I17.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("sql", "hidden"), [
    ("SELECT name FROM employees e JOIN salaries s ON s.employee_id = e.id WHERE s.salary = 6200", "6200"),
    ("SELECT name FROM employees WHERE name = 'Katarzyna Nowak'", "Katarzyna"),
    ("SELECT name FROM employees WHERE name = CAST(x'4b6174' AS TEXT)", "4b6174"),
    ("SELECT salary FROM salaries WHERE salary BETWEEN 6199 AND 6201 OR 1=1", "6199"),
    ("SELECT FROM WHERE 6200 (", "6200"),  # unparsable
])
def test_audit_sql_keeps_no_literal_values(sql: str, hidden: str) -> None:
    from gateway.models import Binding
    from gateway.pipeline import _outcome

    out = _outcome(Binding(name="{x1}", sql=sql, purpose="t", expect="scalar"))
    assert hidden not in out.sql
    assert "FROM" in out.sql.upper()


def test_audit_sql_keeps_tables_columns_and_parameters() -> None:
    from gateway.models import Binding
    from gateway.pipeline import _outcome

    out = _outcome(Binding(name="{x1}", sql="SELECT salary FROM salaries WHERE employee_id = :current_user",
                           purpose="t", expect="scalar"))
    assert "salaries" in out.sql and "employee_id" in out.sql and ":current_user" in out.sql
