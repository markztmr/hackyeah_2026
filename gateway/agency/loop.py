"""Tool loop, mixed-turn rule, limits. Spec section 4 steps 5-6, section 5. Owner: Person 1.

The model sees the gateway system message, the sanitized messages, the client's
tools and the built-in ``query_data``. Each ``query_data`` call becomes a Binding
with the next placeholder and goes validate -> authorize -> execute. The model gets
the bare placeholder unless the binding resolved and ``disclose`` allows more (I7).
The loop is bounded by ``max_tool_iterations`` and ``max_bindings_per_request``,
and the budget is checked before every model call (I11).
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from functools import lru_cache
from typing import Any, get_args

from gateway.binding.authorizer import authorize
from gateway.binding.disclosure import disclose
from gateway.binding.executor import execute
from gateway.binding.sql_validator import validate_sql
from gateway.budget import check_model_and_budget, record_usage
from gateway.inbound.injection import is_query_data_name
from gateway.llm.client import ModelError, ModelProvider, ModelReply, ModelToolCall, call_model, default_provider
from gateway.llm.prompts import QUERY_DATA_TOOL, build_system_message, load_schema
from gateway.models import (
    Binding,
    Decision,
    Expect,
    LoopResult,
    ModelTrust,
    Policy,
    Principal,
    SanitizedRequest,
    ToolCall,
    Vault,
)
from gateway.policy.loader import setting

log = logging.getLogger(__name__)
QUERY_DATA = "query_data"
NOT_EXECUTED = "not executed, re-issue if still needed"
STAGE = "tool_loop"
_EXPECT = frozenset(get_args(Expect))


@lru_cache(maxsize=1)
def _system_message() -> str:
    return build_system_message(load_schema())


def _tool_name(tool: dict[str, Any]) -> str | None:
    fn = tool.get("function") if isinstance(tool, dict) else None
    name = fn.get("name") if isinstance(fn, dict) else tool.get("name") if isinstance(tool, dict) else None
    return name if isinstance(name, str) else None


def _estimate(messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None) -> int:
    """Rough prompt size for the budget pre-check: characters / 4 (the caller adds max_tokens)."""
    return max(1, len(json.dumps([messages, tools], ensure_ascii=False, default=str)) // 4)


def _assistant_message(reply: ModelReply) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": reply.content,
        "tool_calls": [
            {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": c.arguments}}
            for c in reply.tool_calls
        ],
    }


# ---------------------------------------------------------------------------
# One query_data call -> one Binding
# ---------------------------------------------------------------------------


def _parse_query_args(raw: str) -> tuple[str, str, Expect] | None:
    try:
        args = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(args, dict):
        return None
    sql, purpose, expect = args.get("sql"), args.get("purpose"), args.get("expect")
    if not isinstance(sql, str) or not sql.strip() or not isinstance(purpose, str) or expect not in _EXPECT:
        return None
    return sql, purpose, expect


def _resolve(call: ModelToolCall, name: str, over_limit: bool, p: Principal, policy: Policy) -> Binding:
    """Validate, authorize and execute one query_data call. Every failure fails closed (I6)."""
    start = time.perf_counter()
    parsed = _parse_query_args(call.arguments)
    if parsed is None:
        b = Binding(name=name, sql="", purpose="", expect="scalar", status="rejected",
                    reason="Invalid query_data arguments.")
    elif over_limit:
        sql, purpose, expect = parsed
        b = Binding(name=name, sql=sql, purpose=purpose, expect=expect, status="rejected",
                    reason="Binding limit for this request reached; query not executed.")
    else:
        sql, purpose, expect = parsed
        b = Binding(name=name, sql=sql, purpose=purpose, expect=expect)
        steps = (
            (lambda x: validate_sql(x, policy), "rejected", "SQL validation failed internally."),
            (lambda x: authorize(x, p, policy), "denied", "Authorization failed internally."),
            (lambda x: execute(x, p, policy), "error", "Execution failed internally."),
        )
        for step, fail_status, fail_reason in steps:
            try:
                b = step(b)
            except Exception:  # noqa: BLE001 - a failing guardrail denies; never log the message (I8)
                b.status, b.reason = fail_status, fail_reason  # type: ignore[assignment]
            if b.status is not None:
                break
        if b.status is None:
            b.status, b.reason = "error", "Executor returned no outcome."
    if b.status != "resolved":
        b.value = None
    if not b.latency_ms:
        b.latency_ms = (time.perf_counter() - start) * 1000
    return b


_SAFE_FOR_EXTERNAL = frozenset({"public", "internal"})


def _tool_result(b: Binding, p: Principal, policy: Policy, trust: ModelTrust) -> str:
    """What the model sees for a binding: the bare placeholder unless disclosed (I7, I14).

    Two rules are enforced here as well as in ``disclose``: non-resolved bindings
    (rule 1) and, for an external model, anything not known to be below
    ``sensitive`` (rule 4) always get the bare placeholder.
    """
    if b.status != "resolved":
        return b.name
    if trust != "local" and b.label not in _SAFE_FOR_EXTERNAL:
        return b.name
    try:
        shown = disclose(b, p, policy, trust=trust)
    except Exception:  # noqa: BLE001 - fail closed to the placeholder
        return b.name
    if shown == b.name or (isinstance(shown, str) and shown.startswith(f"{b.name} = ")):
        b.disclosed = shown != b.name
        return shown
    return b.name


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


def run_tool_loop(
    req: SanitizedRequest,
    p: Principal,
    vault: Vault,
    policy: Policy,
    *,
    models: ModelProvider | None = None,
    model: str | None = None,
) -> LoopResult:
    """Call the model and resolve query_data calls until final text or client tool calls. Spec section 4 steps 5-6.

    ``model`` is the name chosen in step 2 (default ``models.answer.name``). Blocks
    are returned as a ``block`` decision in ``LoopResult.decisions``.
    """
    result = LoopResult(text=None)

    def block(control: str, reason: str) -> LoopResult:
        result.decisions.append(Decision(STAGE, control, "block", reason))
        return result

    if any(is_query_data_name(_tool_name(t) or "") for t in req.tools):
        return block("tool_definitions", "A client tool is named query_data, which collides with the built-in tool.")

    client = (models or default_provider())("answer", policy)
    model_name = model or setting(policy, "models.answer.name")
    # Every model in models.allowed is served through models.answer, so this is the receiver's trust.
    trust: ModelTrust = setting(policy, "models.answer.trust")
    max_iterations = int(setting(policy, "tool_controls.max_tool_iterations"))
    max_bindings = int(setting(policy, "sql_controls.max_bindings_per_request"))
    tools = [*req.tools, QUERY_DATA_TOOL]
    messages: list[dict[str, Any]] = [{"role": "system", "content": _system_message()}, *req.messages]

    max_tokens = int(setting(policy, "models.answer.max_tokens"))

    def ask(offered: list[dict[str, Any]] | None) -> ModelReply | None:
        try:
            budget = check_model_and_budget(p, model_name, _estimate(messages, offered) + max_tokens, policy)
        except Exception:  # noqa: BLE001 - budget is a guardrail: fail closed (I11)
            budget = Decision(STAGE, "budgets", "block", "Budget check failed.")
        if budget.verdict == "block":
            result.decisions.append(budget)
            return None
        try:
            reply = call_model(client, "answer", policy, messages, offered, model=model_name)
        except ModelError as e:
            # ModelError carries the error type only (never provider text, I8), so it may be logged and shown.
            detail = str(e)
            log.warning("Answer model call failed: %s", detail)
            reason = "The " + detail[:1].lower() + detail[1:] if detail else "The model call failed."
            result.decisions.append(Decision(STAGE, "models.answer", "block", reason))
            return None
        result.prompt_tokens += reply.prompt_tokens
        result.completion_tokens += reply.completion_tokens
        try:  # recorded now, so the next check in this request sees it (I18)
            record_usage(p, reply.prompt_tokens + reply.completion_tokens, model_name, policy)
        except Exception:  # noqa: BLE001 - unrecorded spending must not continue
            result.decisions.append(Decision(STAGE, "budgets", "block", "Usage could not be recorded."))
            return None
        return reply

    retried_empty = False
    for _ in range(max_iterations):
        reply = ask(tools)
        if reply is None:
            return result
        # A small model sometimes returns nothing at all. Ask once more, inside the same
        # iteration bound and through ask(), so the budget is checked before the retry.
        if not reply.tool_calls and not (reply.content or "").strip() and not retried_empty:
            retried_empty = True
            # "allow": a note for the audit record that does not change the request's verdict.
            result.decisions.append(Decision(STAGE, "models.answer", "allow",
                                             "The model returned an empty answer; asked once more."))
            continue
        if not any(c.name == QUERY_DATA for c in reply.tool_calls):
            return _finish(result, reply)

        # Resolve query_data; defer client calls in the same turn (mixed turn).
        result.iterations += 1
        messages.append(_assistant_message(reply))
        for call in reply.tool_calls:
            if call.name == QUERY_DATA:
                name = f"{{x{len(result.bindings) + 1}}}"
                b = _resolve(call, name, len(result.bindings) >= max_bindings, p, policy)
                result.bindings[name] = b
                content = _tool_result(b, p, policy, trust)
            else:
                content = NOT_EXECUTED
            messages.append({"role": "tool", "tool_call_id": call.id, "content": content})

    # Cap reached: one last call with tools disabled. Any tool calls it still proposes are dropped.
    result.decisions.append(Decision(
        STAGE, "tool_controls.max_tool_iterations", "log",
        "Tool iteration limit reached; final answer requested without tools.",
    ))
    reply = ask(None)
    if reply is None:
        return result
    if reply.tool_calls:
        result.decisions.append(Decision(STAGE, "tool_controls.max_tool_iterations", "log",
                                         "Tool calls after the iteration limit were dropped."))
    result.text = reply.content
    return result


MAX_ARGUMENT_DEPTH = 32  # nesting of client tool arguments; deeper is malformed


def _depth(value: Any) -> int:
    """Nesting depth of a parsed JSON value, without recursion."""
    deepest, stack = 0, [(value, 1)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, (dict, list)):
            deepest = max(deepest, d)
            if d <= MAX_ARGUMENT_DEPTH:
                stack.extend((x, d + 1) for x in (v.values() if isinstance(v, dict) else v))
    return deepest


def _finish(result: LoopResult, reply: ModelReply) -> LoopResult:
    """Final text and/or client tool calls; client calls go to step 7 for authorization."""
    result.text = reply.content
    for c in reply.tool_calls:
        try:
            args = json.loads(c.arguments) if c.arguments.strip() else {}
            if _depth(args) > MAX_ARGUMENT_DEPTH:
                args = None
        except Exception:  # noqa: BLE001 - ValueError, RecursionError on deep nesting: malformed
            args = None
        # Arguments that are not a JSON object go to step 7 as the raw string, where
        # tool authorization denies them; the client never receives them. The call id is
        # model output, so the gateway issues its own (it reaches the client unfiltered).
        result.tool_calls.append(ToolCall(id="call_" + uuid.uuid4().hex[:24], name=c.name,
                                          arguments=args if isinstance(args, dict) else c.arguments))
    return result
