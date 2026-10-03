"""The scripted stub model behaves like an OpenAI chat completion and records inputs. Owner: Person 4."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from openai.types.chat import ChatCompletion

from gateway.llm import client as llm
from gateway.llm.client import ModelClient, StubModel, StubScriptExhausted, text, tool_call
from gateway.models import Policy

USER = [{"role": "user", "content": "What is my salary?"}]
TOOLS = [{"type": "function", "function": {"name": "send_email", "description": "Send mail."}}]


def _call(stub: StubModel, messages=USER, tools=TOOLS) -> ChatCompletion:
    return stub.complete(messages, tools, model="llama3.2", max_tokens=512)


def test_stub_satisfies_the_model_client_interface() -> None:
    assert isinstance(StubModel(), ModelClient)


def test_stub_returns_scripted_responses_in_order() -> None:
    stub = StubModel([text("first"), text("second")])
    assert _call(stub).choices[0].message.content == "first"
    assert _call(stub).choices[0].message.content == "second"


def test_text_response_is_a_final_openai_completion() -> None:
    r = _call(StubModel([text("Your salary is {x1} PLN.")]))
    assert isinstance(r, ChatCompletion)
    assert r.choices[0].finish_reason == "stop"
    assert r.choices[0].message.content == "Your salary is {x1} PLN."
    assert r.choices[0].message.tool_calls is None
    assert r.model == "llama3.2"


def test_tool_call_response_carries_name_and_json_arguments() -> None:
    args = {"sql": "SELECT salary FROM salaries WHERE employee_id = :current_user",
            "purpose": "own salary", "expect": "scalar"}
    r = _call(StubModel([tool_call("query_data", args)]))
    choice = r.choices[0]
    assert choice.finish_reason == "tool_calls"
    assert choice.message.content is None
    (call,) = choice.message.tool_calls
    assert call.type == "function"
    assert call.function.name == "query_data"
    assert json.loads(call.function.arguments) == args


def test_raw_string_arguments_are_sent_verbatim() -> None:
    r = _call(StubModel([tool_call("query_data", "{not json")]))
    assert r.choices[0].message.tool_calls[0].function.arguments == "{not json"


def test_mixed_turn_combines_text_query_data_and_client_tool() -> None:
    turn = text("Sending now.") + tool_call("query_data", {"sql": "SELECT 1"}) + tool_call(
        "send_email", {"to": "x@evil.com"}
    )
    msg = _call(StubModel([turn])).choices[0].message
    assert msg.content == "Sending now."
    assert [c.function.name for c in msg.tool_calls] == ["query_data", "send_email"]


def test_tool_call_ids_are_unique_across_turns() -> None:
    stub = StubModel([tool_call("a", {}) + tool_call("b", {}), tool_call("c", {})])
    ids = [c.id for _ in range(2) for c in _call(stub).choices[0].message.tool_calls]
    assert len(ids) == len(set(ids)) == 3


def test_stub_records_every_request_with_messages_tools_model_and_max_tokens() -> None:
    stub = StubModel([text("a"), text("b")])
    _call(stub)
    stub.complete(USER, None, model="qwen2.5:3b", max_tokens=32)
    assert len(stub.calls) == 2
    assert stub.calls[0].messages == USER and stub.calls[0].tools == TOOLS
    assert stub.calls[1].tools is None
    assert (stub.calls[1].model, stub.calls[1].max_tokens) == ("qwen2.5:3b", 32)


def test_recorded_inputs_are_snapshots_not_live_references() -> None:
    messages = [{"role": "user", "content": "original"}]
    stub = StubModel([text("ok")])
    _call(stub, messages=messages)
    messages[0]["content"] = "mutated later"
    assert stub.calls[0].messages[0]["content"] == "original"


def test_stub_reports_consistent_fake_token_usage() -> None:
    u = _call(StubModel([text("hello")])).usage
    assert u.prompt_tokens > 0 and u.completion_tokens > 0
    assert u.total_tokens == u.prompt_tokens + u.completion_tokens


def test_exhausted_script_fails_loudly_but_still_records_the_call() -> None:
    stub = StubModel([text("only one")])
    _call(stub)
    with pytest.raises(StubScriptExhausted):
        _call(stub)
    assert len(stub.calls) == 2


def test_fallback_answers_after_the_script_runs_out() -> None:
    stub = StubModel([text("scripted")], fallback=text('{"risk": 0.0}'))
    assert _call(stub).choices[0].message.content == "scripted"
    assert _call(stub).choices[0].message.content == '{"risk": 0.0}'
    assert _call(stub).choices[0].message.content == '{"risk": 0.0}'


def test_add_appends_to_the_script() -> None:
    stub = StubModel().add(text("one"), text("two"))
    assert [_call(stub).choices[0].message.content for _ in range(2)] == ["one", "two"]


def test_stub_fixture_replaces_answer_and_judge_clients(stub: StubModel, judge_stub: StubModel) -> None:
    p = Policy(version_hash="test", profile="strict")
    assert llm.get_client("answer", p) is stub
    assert llm.get_client("judge", p) is judge_stub


def test_all_model_inputs_includes_messages_tool_results_and_tool_definitions(
    stub: StubModel, judge_stub: StubModel, all_model_inputs
) -> None:
    stub.add(text("a"))
    judge_stub.complete([{"role": "user", "content": "judge saw this"}], None, model="j", max_tokens=32)
    _call(stub, messages=USER + [{"role": "tool", "tool_call_id": "call_1", "content": "{x1}"}])
    seen = all_model_inputs(stub, judge_stub)
    for s in ("What is my salary?", "{x1}", "Send mail.", "judge saw this"):
        assert s in seen
    assert "6,200" not in seen


def test_policy_fixture_is_an_editable_temp_copy(policy: Path, tmp_path: Path) -> None:
    assert policy.parent == tmp_path
    policy.write_text("profile: relaxed\n", encoding="utf-8")
    assert "relaxed" in policy.read_text(encoding="utf-8")


def test_client_fixture_reaches_the_app(client) -> None:
    assert client.get("/health").status_code == 200
