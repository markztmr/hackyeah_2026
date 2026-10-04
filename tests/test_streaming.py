"""Buffered SSE for ``stream: true`` clients (spec section 8 'Inbound stage', section 13 Endpoints).

The pipeline runs in full, output filter included, before anything is sent; the finished
answer then goes out as ``chat.completion.chunk`` events. Tests drive the stock OpenAI SDK
with ``stream=True``, as a streaming chat client would.
"""
from __future__ import annotations

import json
from typing import Any

import openai
import pytest
from fastapi.testclient import TestClient
from openai import OpenAI

from gateway.llm.client import StubModel, text, tool_call
from tests.conftest import INJECTION_PHRASE
from tests.test_e2e import ANNA_SALARY, CEO_SALARY, QUESTION_A, SEND_EMAIL, example_a, forms, query

OWN_SALARY_SQL = "SELECT salary FROM salaries WHERE employee_id = :current_user"


def _sdk(client: TestClient, key: str = "demo-anna") -> OpenAI:
    return OpenAI(base_url="http://testserver/v1", api_key=key, http_client=client)


def _stream(client: TestClient, content: str, key: str = "demo-anna", **body: Any) -> tuple[str, list[Any]]:
    """(reassembled text, chunks) from the SDK's streaming iterator."""
    chunks = list(_sdk(client, key).chat.completions.create(
        model="qwen2.5:3b", messages=[{"role": "user", "content": content}], stream=True, **body))
    return "".join(c.choices[0].delta.content or "" for c in chunks if c.choices), chunks


def test_streaming_client_receives_the_full_answer(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(text("Paris is the capital of France."))
    answer, chunks = _stream(client, "Capital of France?")
    assert answer == "Paris is the capital of France."
    assert chunks[-1].choices[0].finish_reason == "stop"
    assert len({c.id for c in chunks}) == 1 and all(c.object == "chat.completion.chunk" for c in chunks)


def test_stream_is_valid_sse_with_verdict_headers(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(text("Hi."))
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer demo-anna"},
                    json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "Hi"}], "stream": True})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    assert r.headers["x-acl-verdict"] == "allow" and r.headers["x-acl-request-id"]
    events = [line.removeprefix("data: ") for line in r.text.split("\n\n") if line]
    assert events[-1] == "[DONE]"
    first, last = json.loads(events[0]), json.loads(events[-2])
    assert first["choices"][0]["delta"] == {"role": "assistant", "content": "Hi."}
    assert last["choices"][0] == {"index": 0, "delta": {}, "finish_reason": "stop"}


def test_blocked_request_streams_the_reason(client: TestClient, stub: StubModel, fake_steps) -> None:
    raw = _sdk(client).chat.completions.with_raw_response.create(
        model="qwen2.5:3b", messages=[{"role": "user", "content": INJECTION_PHRASE}], stream=True)
    assert raw.headers["x-acl-verdict"] == "block"
    answer = "".join(c.choices[0].delta.content or "" for c in raw.parse() if c.choices)
    assert answer.startswith("Request blocked: ") and "injection" in answer
    assert stub.calls == []  # blocked before any model call, streaming or not


def test_streamed_tool_call_is_reassembled_and_still_authorized(
    client: TestClient, stub: StubModel, fake_steps,
) -> None:
    stub.add(tool_call("send_email", {"to": "anna@company.pl", "body": "Hello"}))
    _, chunks = _stream(client, "Mail me.", tools=[SEND_EMAIL])
    (call,) = [tc for c in chunks if c.choices for tc in (c.choices[0].delta.tool_calls or [])]
    assert call.index == 0 and call.function.name == "send_email"
    assert json.loads(call.function.arguments) == {"to": "anna@company.pl", "body": "Hello"}
    assert chunks[-1].choices[0].finish_reason == "tool_calls"

    # A denied call never appears in the stream either.
    stub.add(tool_call("send_email", {"to": "partner@external.com", "body": "Q3"}))
    answer, chunks = _stream(client, "Mail the partner.", tools=[SEND_EMAIL])
    assert not [tc for c in chunks if c.choices for tc in (c.choices[0].delta.tool_calls or [])]
    assert answer == "The action send_email was blocked by policy." and "external.com" not in answer


def test_streamed_answer_is_filled_and_filtered_like_a_plain_one(
    client: TestClient, stub: StubModel, judge_stub: StubModel, db, all_model_inputs,  # noqa: ANN001
) -> None:
    plain = example_a(client, stub).json()["choices"][0]["message"]["content"]
    stub.add(query(OWN_SALARY_SQL, "own salary") + query("SELECT salary FROM salaries WHERE employee_id = 'katarzyna'"),
             text("Your salary is {x1} PLN. The CEO earns {x2} PLN."))
    streamed, _ = _stream(client, QUESTION_A)
    assert streamed == plain == "Your salary is 6200 PLN. The CEO earns [UNAVAILABLE] PLN."
    seen = all_model_inputs(stub, judge_stub)
    for value in (ANNA_SALARY, CEO_SALARY):
        assert not any(f in seen for f in forms(value)), value


def test_non_streaming_requests_are_unchanged(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(text("Plain."))
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer demo-anna"},
                    json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "Hi"}], "stream": False})
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["choices"][0]["message"]["content"] == "Plain."


def test_streaming_with_a_bad_key_is_a_plain_401(client: TestClient, stub: StubModel) -> None:
    with pytest.raises(openai.AuthenticationError):
        _stream(client, "Hi", key="nope")
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer nope"},
                    json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "Hi"}], "stream": True})
    assert r.status_code == 401 and r.headers["content-type"].startswith("application/json")
    assert stub.calls == []


def test_stream_options_from_stock_clients_are_accepted(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(text("Ok."))
    answer, _ = _stream(client, "Hi", stream_options={"include_usage": True})
    assert answer == "Ok."
