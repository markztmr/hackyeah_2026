"""OpenAI-compatible adapter (Ollama + external) and the scripted stub. Spec sections 13, 14. Owner: Person 1 (stub: Person 4).

Every model call goes through a ``ModelClient``. Callers obtain one with
``gateway.llm.client.get_client(purpose, policy)`` and must look it up through the
module (``from gateway.llm import client as llm; llm.get_client(...)``) so tests can
replace it with a ``StubModel``.
"""
from __future__ import annotations

import copy
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

from openai.types.chat import ChatCompletion

from gateway.models import Policy

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


def get_client(purpose: Purpose, policy: Policy) -> ModelClient:
    """Client for ``models.answer`` or ``models.judge`` of this policy snapshot."""
    raise NotImplementedError


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
