"""Model client: one interface for the stub and the OpenAI-compatible adapter. Spec sections 3, 6, 13. Owner: Person 1."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from openai.types.chat import ChatCompletion

from gateway.llm import client as llm
from gateway.llm.client import (
    ModelClient,
    ModelError,
    OpenAICompatibleClient,
    StubModel,
    call_model,
    get_client,
    text,
    tool_call,
)
from gateway.policy.loader import parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
USER = [{"role": "user", "content": "How many products are there?"}]


@pytest.fixture
def base() -> dict[str, Any]:
    return copy.deepcopy(yaml.safe_load((REPO_ROOT / "policy.yaml").read_text(encoding="utf-8")))


@pytest.fixture
def shipped():
    return parse_policy((REPO_ROOT / "policy.yaml").read_bytes())


def _policy(data: dict[str, Any]):
    return parse_policy(yaml.safe_dump(data).encode("utf-8"))


# ---------------------------------------------------------------------------
# call_model with the stub
# ---------------------------------------------------------------------------


def test_stub_and_real_client_share_one_interface() -> None:
    assert isinstance(StubModel(), ModelClient)
    assert isinstance(OpenAICompatibleClient(base_url="http://127.0.0.1:1/v1", timeout_s=1.0), ModelClient)


@pytest.mark.parametrize(("purpose", "max_tokens"), [("answer", 512), ("judge", 32)])
def test_every_call_sets_max_tokens_from_the_policy(shipped, purpose: str, max_tokens: int) -> None:
    stub = StubModel([text("ok")])
    call_model(stub, purpose, shipped, USER)
    assert stub.calls[0].max_tokens == max_tokens


def test_call_uses_the_policy_model_name_unless_one_is_given(shipped) -> None:
    stub = StubModel([text("a"), text("b")])
    call_model(stub, "answer", shipped, USER)
    call_model(stub, "answer", shipped, USER, model="qwen2.5:1.5b")
    assert [c.model for c in stub.calls] == ["qwen2.5:3b", "qwen2.5:1.5b"]


def test_reply_carries_content_tool_calls_and_usage(shipped) -> None:
    sql = {"sql": "SELECT count(*) FROM products", "purpose": "count", "expect": "scalar"}
    stub = StubModel([text("Let me check.") + tool_call("query_data", sql)])
    reply = call_model(stub, "answer", shipped, USER, tools=[{"type": "function", "function": {"name": "x"}}])

    assert reply.content == "Let me check."
    assert [(c.name, json.loads(c.arguments)) for c in reply.tool_calls] == [("query_data", sql)]
    assert reply.tool_calls[0].id
    assert reply.prompt_tokens > 0 and reply.completion_tokens > 0
    assert reply.usage_estimated is False
    assert stub.calls[0].tools is not None


def test_no_tools_means_tools_are_not_sent(shipped) -> None:
    stub = StubModel([text("ok")])
    call_model(stub, "answer", shipped, USER)
    assert stub.calls[0].tools is None


class _NoUsage:
    """A provider that omits ``usage``."""

    def complete(self, messages, tools, *, model, max_tokens) -> ChatCompletion:
        return ChatCompletion.model_validate({
            "id": "x", "object": "chat.completion", "created": 0, "model": model,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "a" * 40}}],
        })


def test_missing_usage_is_estimated_as_characters_over_four(shipped) -> None:
    reply = call_model(_NoUsage(), "answer", shipped, USER)
    assert reply.usage_estimated is True
    assert reply.completion_tokens == len(json.dumps(["a" * 40, []])) // 4
    assert reply.prompt_tokens == len(json.dumps([USER, None])) // 4


def test_reply_repr_never_shows_content_or_arguments(shipped) -> None:
    stub = StubModel([text("salary is 6200") + tool_call("send_email", {"body": "6200"})])
    assert "6200" not in repr(call_model(stub, "answer", shipped, USER))


# ---------------------------------------------------------------------------
# The real client, against a fake HTTP transport (no network)
# ---------------------------------------------------------------------------


def _completion_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": "c1", "object": "chat.completion", "created": 0, "model": "qwen2.5:3b",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "Hi."}}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 2, "total_tokens": 9},
    }
    body.update(overrides)
    return body


def _real(handler, **kwargs: Any) -> OpenAICompatibleClient:
    return OpenAICompatibleClient(
        base_url="http://ollama.test/v1", timeout_s=kwargs.pop("timeout_s", 7.5),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)), **kwargs,
    )


def test_real_client_posts_to_base_url_with_max_tokens_and_tools(shipped) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_completion_body())

    tools = [{"type": "function", "function": {"name": "query_data", "parameters": {"type": "object"}}}]
    reply = call_model(_real(handler), "answer", shipped, USER, tools=tools)

    assert str(seen[0].url) == "http://ollama.test/v1/chat/completions"
    sent = json.loads(seen[0].content)
    assert sent["max_tokens"] == 512
    assert sent["model"] == "qwen2.5:3b"
    assert sent["tools"] == tools
    assert (reply.content, reply.prompt_tokens, reply.completion_tokens) == ("Hi.", 7, 2)


def test_real_client_omits_tools_when_none_are_offered(shipped) -> None:
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json=_completion_body())

    call_model(_real(handler), "answer", shipped, USER)
    assert "tools" not in seen[0]


def test_real_client_sets_a_timeout() -> None:
    assert _real(lambda r: httpx.Response(200)).timeout_s == 7.5


def test_real_client_estimates_usage_when_the_provider_omits_it(shipped) -> None:
    body = _completion_body()
    del body["usage"]
    reply = call_model(_real(lambda r: httpx.Response(200, json=body)), "answer", shipped, USER)
    assert reply.usage_estimated is True
    assert reply.prompt_tokens > 0


def test_timeout_becomes_a_model_error(shipped) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    with pytest.raises(ModelError):
        call_model(_real(handler), "answer", shipped, USER)


def test_provider_error_does_not_echo_the_response_body(shipped) -> None:
    """I8: provider errors can quote the prompt; ModelError carries the error type only."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": {"message": "bad prompt: salary 6200"}})

    with pytest.raises(ModelError) as exc:
        call_model(_real(handler), "answer", shipped, USER)
    assert "6200" not in str(exc.value)
    assert exc.value.__cause__ is None and exc.value.__suppress_context__


def test_no_retries_so_one_call_is_one_request(shipped) -> None:
    count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal count
        count += 1
        return httpx.Response(503)

    with pytest.raises(ModelError):
        call_model(_real(handler), "answer", shipped, USER)
    assert count == 1


# ---------------------------------------------------------------------------
# get_client: built from the policy snapshot
# ---------------------------------------------------------------------------


def test_get_client_builds_the_client_from_the_policy(base: dict[str, Any]) -> None:
    base["models"]["answer"]["base_url"] = "http://127.0.0.1:9999/v1"
    base["models"]["answer"]["timeout_s"] = 12
    c = get_client("answer", _policy(base))
    assert isinstance(c, OpenAICompatibleClient)
    assert c.base_url == "http://127.0.0.1:9999/v1"
    assert c.timeout_s == 12


def test_external_provider_without_an_api_key_fails_closed(base: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    base["models"]["answer"].update(provider="openai_compatible", base_url="https://api.example.com/v1", trust="external")
    with pytest.raises(ModelError):
        get_client("answer", _policy(base))


def test_external_judge_is_refused(base: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """Spec section 3: the judge model is local only."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    base["models"]["judge"].update(provider="openai_compatible", base_url="https://api.example.com/v1", trust="external")
    with pytest.raises(ModelError):
        get_client("judge", _policy(base))


def test_stub_fixture_is_what_the_default_provider_returns(stub: StubModel, shipped) -> None:
    """Callers that are not given a provider look it up through the module, so tests can swap it."""
    assert llm.default_provider()("answer", shipped) is stub


def test_judge_client_runs_at_temperature_zero_and_the_answer_client_at_the_default() -> None:
    from gateway.llm.client import JUDGE_TEMPERATURE, OpenAICompatibleClient, get_client
    from gateway.policy.loader import load_policy

    pol = load_policy(Path(__file__).resolve().parent.parent / "policy.yaml")
    judge_client, answer_client = get_client("judge", pol), get_client("answer", pol)
    assert isinstance(judge_client, OpenAICompatibleClient) and judge_client.temperature == JUDGE_TEMPERATURE == 0.0
    assert isinstance(answer_client, OpenAICompatibleClient) and answer_client.temperature is None
