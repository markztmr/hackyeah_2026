"""The 10 pipeline steps, in order. Orchestration only. Spec section 4. Owner: Person 1.

Contract with main.py:
- returns ``(ChatResponse, verdict)``; a block is an assistant message with the reason (HTTP 200);
- raises ``AuthError`` for an unknown key (HTTP 401);
- raises ``GatewayError`` for anything unexpected (HTTP 500, no details);
- writes exactly one audit record per call, in ``finally`` (I12/I17). If the audit
  write itself fails, the request fails: no answer leaves without its record.
"""
from __future__ import annotations

import json
import logging
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any

from gateway.agency.loop import run_tool_loop
from gateway.agency.tool_authz import authorize_tool_call
from gateway.audit import write_audit
from gateway.auth import AuthError, authenticate
from gateway.budget import check_model_and_budget, cost_usd, record_usage, resolve_model
from gateway.inbound.history import record_issued
from gateway.inbound.injection import check_injection, safe_tool_label
from gateway.inbound.judge import judge
from gateway.inbound.masker import client_texts, inspect_inbound, redact_sensitive
from gateway.inbound.signatures import match_signatures
from gateway.llm.client import ModelProvider, default_provider
from gateway.models import (
    AuditRecord,
    Binding,
    BindingOutcome,
    ChatRequest,
    ChatResponse,
    Decision,
    FilledText,
    IssuedCache,
    Policy,
    Principal,
    SanitizedRequest,
    SignatureFeed,
    ToolCall,
    ToolDecision,
    Verdict,
)
from gateway.outbound.fill import fill
from gateway.outbound.output_filter import filter_output
from gateway.policy.loader import setting
from gateway.telemetry import Metrics, StepTimer

log = logging.getLogger(__name__)

_SEVERITY: dict[str, int] = {"allow": 0, "log": 1, "redact": 2, "block": 3}


class GatewayError(Exception):
    """Unexpected failure. main.py returns HTTP 500 with only the request ID (I8)."""

    def __init__(self, request_id: str) -> None:
        super().__init__("Internal gateway error.")
        self.request_id = request_id


class _Blocked(Exception):
    """A check blocked the request; carries the decision whose reason the user sees."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision


# ---------------------------------------------------------------------------
# Helpers (no checks here; checks live in their modules)
# ---------------------------------------------------------------------------


def _stop_on_block(decisions: list[Decision]) -> None:
    for d in decisions:
        if d.verdict == "block":
            raise _Blocked(d)


def _estimate(obj: Any) -> int:
    """Token estimate for the budget pre-check: characters / 4."""
    return max(1, len(json.dumps(obj, ensure_ascii=False, default=str)) // 4)


def _text(content: Any) -> str:
    """Text of an OpenAI message content: a string or a list of parts."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("text", "") for p in content if isinstance(p, dict) and isinstance(p.get("text"), str))
    return ""


_TOOL_RESULT_ROLES = frozenset({"tool", "function"})


def _role(m: dict[str, Any]) -> str:
    role = m.get("role")
    return role.strip().lower() if isinstance(role, str) else ""


def _all_input(sanitized: SanitizedRequest) -> list[tuple[str, str]]:
    """(surface, text) for the phrase and signature checks: every client message, whatever its role.

    The client owns the whole history, so system, developer and forged assistant
    turns, older tool results, ``name`` fields and tool-call arguments are all checked.
    """
    out: list[tuple[str, str]] = []
    for m in sanitized.messages:
        surface = "tool_result" if _role(m) in _TOOL_RESULT_ROLES else "input"
        out += [(surface, t) for t in client_texts([m]) if t]
    return out


def _new_input(sanitized: SanitizedRequest) -> list[tuple[str, str]]:
    """(surface, text) for the judge: the newest user message and tool results after the last assistant turn.

    Spec section 4 step 4 limits the judge to new content; older turns get the deterministic checks.
    """
    out: list[tuple[str, str]] = []
    for m in reversed(sanitized.messages):
        role = _role(m)
        if role in _TOOL_RESULT_ROLES:
            out.append(("tool_result", _text(m.get("content"))))
        elif role == "user":
            out.append(("input", _text(m.get("content"))))
            break
        elif role == "assistant":
            break
    return [(s, t) for s, t in reversed(out) if t]


def _map_leaves(value: Any, fn: Any) -> Any:
    """Apply ``fn`` to every text leaf (str or FilledText) of a JSON-like tool argument value."""
    if isinstance(value, (str, FilledText)):
        return fn(value)
    if isinstance(value, dict):
        return {k: _map_leaves(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [_map_leaves(v, fn) for v in value]
    return value


def _outcome(b: Binding) -> BindingOutcome:
    """Audit view of a binding: everything except the value (I8)."""
    return BindingOutcome(
        # sql and purpose are model-written: secrets and PII in them never reach the audit log (I8).
        name=b.name, sql=redact_sensitive(b.sql), purpose=redact_sensitive(b.purpose),
        status=b.status, label=b.label, disclosed=b.disclosed,
        reason=b.reason, tables=list(b.tables), columns=list(b.columns), rows=b.rows,
        truncated=b.truncated, latency_ms=b.latency_ms,
    )


def _response(request_id: str, model: str, content: str, tool_calls: list[ToolCall],
              prompt_tokens: int = 0, completion_tokens: int = 0) -> ChatResponse:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = [
            {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
            for c in tool_calls
        ]
    return ChatResponse(
        id=request_id,
        created=int(time.time()),
        model=model,
        choices=[{"index": 0, "message": message, "finish_reason": "tool_calls" if tool_calls else "stop"}],
        usage={"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
               "total_tokens": prompt_tokens + completion_tokens},
    )


def _new_record(policy: Policy, feed: SignatureFeed) -> AuditRecord:
    return AuditRecord(
        request_id=uuid.uuid4().hex,
        timestamp=datetime.now(timezone.utc).isoformat(),
        policy_version=policy.version_hash,
        feed_version=feed.version,
        verdict="block",  # until the request completes
        disabled_controls=list(policy.disabled_controls),
    )


def _where(e: BaseException) -> str:
    """Last frame of an exception as file:line, for logs. Never the message, which may hold values."""
    frames = traceback.extract_tb(e.__traceback__)
    return f"{frames[-1].filename}:{frames[-1].lineno}" if frames else "unknown"


# ---------------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------------


def run_pipeline(
    api_key: str,
    req: ChatRequest,
    policy: Policy,
    feed: SignatureFeed,
    cache: IssuedCache,
    *,
    models: ModelProvider | None = None,
    metrics: Metrics | None = None,
) -> tuple[ChatResponse, Verdict]:
    """Run one request through the 10 steps. Spec section 4.

    ``policy`` and ``feed`` are the snapshot taken at the start of the request and
    are used unchanged until the end (I14/I16). ``models`` picks the model client per
    purpose; tests inject the stub, production uses ``get_client``.
    """
    timer = StepTimer()
    record = _new_record(policy, feed)
    try:
        response = _run(api_key, req, policy, feed, cache, models or default_provider(), timer, record)
        return response, record.verdict
    except AuthError:
        record.verdict = "block"
        record.decisions.append(Decision("authenticate", "core.authentication", "block", "Invalid or missing API key."))
        raise
    except Exception as e:  # noqa: BLE001 - anything unexpected fails closed with a safe error
        record.verdict = "block"
        record.decisions.append(Decision("pipeline", "internal_error", "block", f"Internal error ({type(e).__name__})."))
        log.error("Request %s failed: %s at %s", record.request_id, type(e).__name__, _where(e))
        raise GatewayError(record.request_id) from None
    finally:
        record.step_latency_ms = dict(timer.steps)
        record.total_latency_ms = timer.total_ms()
        try:
            write_audit(record, policy)
        except Exception as e:  # noqa: BLE001
            log.error("Audit write failed for request %s: %s", record.request_id, type(e).__name__)
            raise GatewayError(record.request_id) from None  # replaces any answer: no record, no answer
        finally:
            if metrics is not None:
                metrics.record(record.verdict, record.step_latency_ms, record.total_latency_ms)


def _run(
    api_key: str,
    req: ChatRequest,
    policy: Policy,
    feed: SignatureFeed,
    cache: IssuedCache,
    models: ModelProvider,
    timer: StepTimer,
    record: AuditRecord,
) -> ChatResponse:
    model_name = req.model
    try:
        # Step 1: authenticate. The policy snapshot was taken by the caller. I2, I16.
        with timer.step("authenticate"):
            p = authenticate(api_key, policy)
        record.user_id, record.role, record.department, record.ai_data_policy = (
            p.user_id, p.role, p.department, p.ai_data_policy)

        # Step 2: model allowlist, then budget pre-check. I11.
        with timer.step("model_and_budget"):
            resolved, model_decision = resolve_model(req.model, policy)
            record.decisions.append(model_decision)
            if resolved is None:
                raise _Blocked(model_decision)
            model_name = record.answer_model = resolved
            estimate = _estimate([[m.model_dump(exclude_none=True) for m in req.messages], req.tools])
            budget = check_model_and_budget(p, model_name, estimate, policy)
            record.decisions.append(budget)
            _stop_on_block([budget])

        # Step 3: inbound inspection (mask, re-mask history, scan tool definitions).
        with timer.step("inbound"):
            sanitized, vault, inbound = inspect_inbound(req, p, policy, cache)
            record.decisions.extend(inbound)
            _stop_on_block(inbound)

        # Step 4: input checks on new content: phrases, feed, then the judge (budget first).
        with timer.step("input_checks"):
            _input_checks(sanitized, p, policy, feed, models, record)

        # Steps 5-6: model call and bounded query_data loop.
        with timer.step("model_and_tool_loop"):
            loop = run_tool_loop(sanitized, p, vault, policy, models=models, model=model_name)
            record.decisions.extend(loop.decisions)
            record.bindings = [_outcome(b) for b in loop.bindings.values()]
            record.tool_iterations = loop.iterations
            record.prompt_tokens, record.completion_tokens = loop.prompt_tokens, loop.completion_tokens
            _stop_on_block(loop.decisions)

        # Step 7: authorize client tool calls; denied calls are removed.
        with timer.step("tool_authz"):
            allowed = _authorize_tools(loop.tool_calls, p, loop.bindings, policy, record)

        # Step 8: outbound fill, single literal pass, on the answer and allowed tool arguments.
        with timer.step("fill"):
            filled = fill(loop.text or "", loop.bindings, vault, policy)
            filled_args = [
                (c, _map_leaves(c.arguments, lambda s: fill(s, loop.bindings, vault, policy))) for c in allowed
            ]

        # Step 9: output filter on every answer and every allowed tool call's arguments. I10.
        with timer.step("output_filter"):
            # Signatures on what the model wrote: the answer before fill, and client tool arguments.
            scans = [match_signatures(loop.text or "", "model_output", feed, policy)]
            scans += [match_signatures(json.dumps(c.arguments, ensure_ascii=False), "tool_args", feed, policy)
                      for c in allowed]
            record.decisions.extend(scans)
            _stop_on_block(scans)
            answer, out = filter_output(filled, p, policy)
            record.decisions.append(out)
            _stop_on_block([out])
            calls = _filter_tool_args(filled_args, p, policy, record)

        # Step 10: usage, issued values; the audit record is written by the caller.
        with timer.step("record"):
            tokens = record.prompt_tokens + record.completion_tokens
            record_usage(p, tokens, model_name, policy)
            record.cost_usd = cost_usd(model_name, tokens, policy)
            record_issued(p, loop.bindings, cache)

        if loop.tool_calls and not calls and not answer:
            names = ", ".join(dict.fromkeys(safe_tool_label(c.name, i) for i, c in enumerate(loop.tool_calls)))
            record.verdict = "block"
            return _response(record.request_id, model_name, f"The action {names} was blocked by policy.", [],
                             record.prompt_tokens, record.completion_tokens)
        record.verdict = _final_verdict(record)
        return _response(record.request_id, model_name, answer, calls, record.prompt_tokens, record.completion_tokens)
    except _Blocked as b:
        record.verdict = "block"
        return _response(record.request_id, model_name, f"Request blocked: {b.decision.reason}", [],
                         record.prompt_tokens, record.completion_tokens)


def _input_checks(
    sanitized: SanitizedRequest, p: Principal, policy: Policy, feed: SignatureFeed,
    models: ModelProvider, record: AuditRecord,
) -> None:
    flagged = False
    for surface, text in _all_input(sanitized):
        for d in (check_injection(text, policy), match_signatures(text, surface, feed, policy)):
            if d.verdict != "allow":
                flagged = True
                record.decisions.append(d)
                _stop_on_block([d])
    if not flagged:
        record.decisions.append(Decision("input_checks", "injection", "allow", ""))
        record.decisions.append(Decision("input_checks", "signatures", "allow", ""))
    items = _new_input(sanitized)
    if not items or not setting(policy, "prompt_controls.semantic.enabled"):
        return
    combined = "\n\n".join(t for _, t in items)
    judge_model = record.judge_model = setting(policy, "models.judge.name")
    budget = check_model_and_budget(p, judge_model, _estimate(combined), policy)
    record.decisions.append(budget)
    _stop_on_block([budget])
    verdict = judge(combined, policy, models=models)
    record.decisions.append(verdict)
    _stop_on_block([verdict])


def _authorize_tools(
    calls: list[ToolCall], p: Principal, bindings: dict[str, Binding], policy: Policy, record: AuditRecord,
) -> list[ToolCall]:
    allowed: list[ToolCall] = []
    for c in calls:
        try:
            td = authorize_tool_call(c, p, bindings, policy)
        except Exception:  # noqa: BLE001 - a failing check denies (I6)
            td = ToolDecision(c.name, "deny", "internal_error", "Tool authorization failed.")
        record.tool_decisions.append(td)
        if td.verdict == "allow":
            allowed.append(c)
    return allowed


def _filter_tool_args(
    filled_args: list[tuple[ToolCall, Any]], p: Principal, policy: Policy, record: AuditRecord,
) -> list[ToolCall]:
    out: list[ToolCall] = []
    for call, args in filled_args:
        decisions: list[Decision] = []

        def check(f: FilledText) -> str:
            text, d = filter_output(f, p, policy)
            decisions.append(d)
            return text

        filtered = _map_leaves(args, check)
        record.decisions.extend(decisions)
        if any(d.verdict == "block" for d in decisions):
            record.tool_decisions.append(ToolDecision(call.name, "deny", "output_filter", "Output filter blocked the arguments."))
            continue
        out.append(ToolCall(id=call.id, name=call.name, arguments=filtered))
    return out


def _final_verdict(record: AuditRecord) -> Verdict:
    worst = max((_SEVERITY[d.verdict] for d in record.decisions), default=0)
    if any(t.verdict == "deny" for t in record.tool_decisions):
        worst = max(worst, _SEVERITY["redact"])
    return next(v for v, s in _SEVERITY.items() if s == worst)  # type: ignore[return-value]


def audit_rejected_request(policy: Policy, feed: SignatureFeed, reason: str, metrics: Metrics | None = None) -> str:
    """One audit record for a request rejected before the pipeline (e.g. invalid body). Returns its ID."""
    record = _new_record(policy, feed)
    record.decisions.append(Decision("request", "request_body", "block", reason))
    write_audit(record, policy)
    if metrics is not None:
        metrics.record("block", {}, 0.0)
    return record.request_id
