"""OpenAI-compatible adapter (Ollama + external) and the scripted stub. Spec sections 13, 14. Owner: Person 1 (stub: Person 4).

Every model call goes through a ``ModelClient``. Callers obtain one with
``gateway.llm.client.get_client(purpose, policy)`` and must look it up through the
module (``from gateway.llm import client as llm; llm.get_client(...)``) so tests can
replace it with a ``StubModel``.
"""
from __future__ import annotations

import copy
import json
import os
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

import httpx
from openai import OpenAI, OpenAIError
from openai.types.chat import ChatCompletion

from gateway.models import Policy
from gateway.policy.loader import setting

Purpose = Literal["answer", "judge"]


@runtime_checkable
class ModelClient(Protocol):
    """One chat-completion call. ``tools=None`` means tools disabled.

    ``max_tokens`` is required on every call (CLAUDE.md conventions).
    """

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        *,
        model: str,
        max_tokens: int,
    ) -> ChatCompletion: ...


ModelProvider = Callable[[Purpose, Policy], ModelClient]
"""Picks the client for a purpose. The pipeline takes one by injection; tests pass the stub."""


class ModelError(Exception):
    """A model call failed (timeout, HTTP error, bad response). Carries the error type only, never content (I8)."""


# ---------------------------------------------------------------------------
# OpenAI-compatible adapter: Ollama and external providers share this path
# ---------------------------------------------------------------------------


class OpenAICompatibleClient:
    """``ModelClient`` over the openai SDK. One instance per base URL, key, timeout and temperature.

    No retries: one ``complete`` is one HTTP request, so budget and latency stay exact.
    ``temperature`` None leaves the provider default; the judge uses 0 for stable scores.
    """

    def __init__(
        self,
        base_url: str,
        timeout_s: float,
        api_key: str = "ollama",  # Ollama ignores the key; the SDK requires one
        http_client: httpx.Client | None = None,
        temperature: float | None = None,
    ) -> None:
        self.base_url = base_url
        self.timeout_s = timeout_s
        self.temperature = temperature
        self._sdk = OpenAI(
            base_url=base_url, api_key=api_key, timeout=timeout_s, max_retries=0, http_client=http_client,
        )

    def __repr__(self) -> str:
        return f"OpenAICompatibleClient(base_url={self.base_url!r}, timeout_s={self.timeout_s})"

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        *,
        model: str,
        max_tokens: int,
    ) -> ChatCompletion:
        kwargs: dict[str, Any] = {"model": model, "messages": messages, "max_tokens": max_tokens}
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if tools:
            kwargs["tools"] = tools
        return self._sdk.chat.completions.create(**kwargs)


JUDGE_TEMPERATURE = 0.0  # a classifier: the same content should get the same score
_clients: dict[tuple[str, str, float, float | None], OpenAICompatibleClient] = {}


def get_client(purpose: Purpose, policy: Policy) -> ModelClient:
    """Client for ``models.answer`` or ``models.judge`` of this policy snapshot."""
    cfg = setting(policy, f"models.{purpose}")
    if purpose == "judge" and (cfg["trust"] != "local" or cfg["provider"] != "ollama"):
        raise ModelError("The judge model must be a local Ollama model.")
    if cfg["provider"] == "ollama":
        api_key = "ollama"
    else:
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            raise ModelError("OPENAI_API_KEY is not set for the external model provider.")
    temperature = JUDGE_TEMPERATURE if purpose == "judge" else None
    key = (cfg["base_url"], api_key, float(cfg["timeout_s"]), temperature)
    if key not in _clients:
        _clients[key] = OpenAICompatibleClient(cfg["base_url"], float(cfg["timeout_s"]), api_key, temperature=temperature)
    return _clients[key]


def ping(purpose: Purpose, policy: Policy, timeout_s: float = 1.0) -> bool:
    """Whether ``models.<purpose>`` answers HTTP at all (GET {base_url}/models). For /health only."""
    base_url = setting(policy, f"models.{purpose}.base_url").rstrip("/")
    try:
        return httpx.get(f"{base_url}/models", timeout=timeout_s).status_code < 500
    except httpx.HTTPError:
        return False


def default_provider() -> ModelProvider:
    """``get_client``, looked up through the module at call time so tests can replace it."""
    import gateway.llm.client as module

    return module.get_client


# ---------------------------------------------------------------------------
# One call, normalized
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ModelToolCall:
    """A tool call as the model proposed it. ``arguments`` is raw JSON text, parsed by the caller."""

    id: str
    name: str
    arguments: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ModelReply:
    """Content, tool calls and token usage of one model call. Content is excluded from repr (I8)."""

    content: str | None = field(repr=False)
    tool_calls: tuple[ModelToolCall, ...]
    prompt_tokens: int
    completion_tokens: int
    usage_estimated: bool
    finish_reason: str | None


def call_model(
    client: ModelClient,
    purpose: Purpose,
    policy: Policy,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    *,
    model: str | None = None,
) -> ModelReply:
    """Make one model call with ``max_tokens`` from ``models.<purpose>`` and normalize the result.

    The caller checks the budget before calling (I11). Usage the provider omits is
    estimated as characters / 4.
    """
    max_tokens = int(setting(policy, f"models.{purpose}.max_tokens"))
    name = model or setting(policy, f"models.{purpose}.name")
    try:
        completion = client.complete(messages, tools or None, model=name, max_tokens=max_tokens)
        choice = completion.choices[0]
        message = choice.message
        calls = tuple(
            ModelToolCall(id=c.id, name=c.function.name, arguments=c.function.arguments or "")
            for c in (message.tool_calls or [])
            if getattr(c, "function", None) is not None
        )
        content = message.content
        finish_reason = choice.finish_reason
        usage = completion.usage
    except (OpenAIError, httpx.HTTPError) as e:
        raise ModelError(f"Model call failed: {type(e).__name__}.") from None
    except (IndexError, AttributeError, TypeError, ValueError) as e:
        raise ModelError(f"Model returned an unusable response: {type(e).__name__}.") from None

    if usage is not None and usage.prompt_tokens is not None and usage.completion_tokens is not None:
        prompt, completion_tokens, estimated = usage.prompt_tokens, usage.completion_tokens, False
    else:
        prompt = _token_count([messages, tools or None])
        completion_tokens = _token_count([content, [{"name": c.name, "arguments": c.arguments} for c in calls]])
        estimated = True
    return ModelReply(content, calls, prompt, completion_tokens, estimated, finish_reason)


# ---------------------------------------------------------------------------
# Scripted stub (spec section 14, "Determinism")
# ---------------------------------------------------------------------------


class StubScriptExhausted(AssertionError):
    """The model was called more times than the test scripted."""


@dataclass(frozen=True, slots=True)
class StubToolCall:
    name: str
    arguments: str  # JSON text, exactly as an OpenAI model returns it


@dataclass(frozen=True, slots=True)
class StubResponse:
    """One scripted model turn. Combine with ``+``: ``text("a") + tool_call(...)``."""

    content: str | None = None
    tool_calls: tuple[StubToolCall, ...] = ()

    def __add__(self, other: StubResponse) -> StubResponse:
        if self.content is not None and other.content is not None:
            content: str | None = self.content + other.content
        else:
            content = self.content if self.content is not None else other.content
        return StubResponse(content, self.tool_calls + other.tool_calls)


def text(content: str) -> StubResponse:
    """A turn with final text."""
    return StubResponse(content=content)


def tool_call(name: str, args: dict[str, Any] | str) -> StubResponse:
    """A turn with one tool call. ``args`` as str is sent verbatim (e.g. malformed JSON)."""
    arguments = args if isinstance(args, str) else json.dumps(args)
    return StubResponse(tool_calls=(StubToolCall(name, arguments),))


@dataclass(frozen=True, slots=True)
class StubCall:
    """One request the stub received, deep-copied at call time."""

    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]] | None
    model: str
    max_tokens: int


def _token_count(obj: Any) -> int:
    """Fake, deterministic token count: one token per 4 characters, at least 1."""
    return max(1, len(json.dumps(obj, ensure_ascii=False, default=str)) // 4)


@dataclass
class StubModel:
    """Scripted ``ModelClient``: returns ``script`` in order and records every input.

    When the script runs out, ``fallback`` is returned if set; otherwise the call
    raises ``StubScriptExhausted``.
    """

    script: deque[StubResponse] = field(default_factory=deque)
    fallback: StubResponse | None = None
    calls: list[StubCall] = field(default_factory=list)
    _next_call_id: int = field(default=0, repr=False)

    def __post_init__(self) -> None:
        self.script = deque(self.script)

    def add(self, *responses: StubResponse) -> StubModel:
        """Append responses to the script; returns self for chaining."""
        self.script.extend(responses)
        return self

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        *,
        model: str,
        max_tokens: int,
    ) -> ChatCompletion:
        self.calls.append(StubCall(copy.deepcopy(messages), copy.deepcopy(tools), model, max_tokens))
        if self.script:
            response = self.script.popleft()
        elif self.fallback is not None:
            response = self.fallback
        else:
            raise StubScriptExhausted(f"stub called {len(self.calls)} times; script has no response left")
        return self._completion(response, model, _token_count([messages, tools]))

    def _completion(self, r: StubResponse, model: str, prompt_tokens: int) -> ChatCompletion:
        calls = []
        for tc in r.tool_calls:
            self._next_call_id += 1
            calls.append(
                {
                    "id": f"call_{self._next_call_id}",
                    "type": "function",
                    "function": {"name": tc.name, "arguments": tc.arguments},
                }
            )
        message: dict[str, Any] = {"role": "assistant", "content": r.content}
        if calls:
            message["tool_calls"] = calls
        completion_tokens = _token_count([r.content, [c["function"] for c in calls]])
        return ChatCompletion.model_validate(
            {
                "id": f"stub-{len(self.calls)}",
                "object": "chat.completion",
                "created": 0,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": "tool_calls" if calls else "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                },
            }
        )
