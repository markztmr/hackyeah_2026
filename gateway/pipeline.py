"""The 10 pipeline steps, in order. Orchestration only. Spec section 4. Owner: Person 1."""
from __future__ import annotations

from gateway.agency.loop import run_tool_loop
from gateway.agency.tool_authz import authorize_tool_call
from gateway.audit import write_audit
from gateway.auth import authenticate
from gateway.budget import check_model_and_budget, record_usage
from gateway.inbound.history import record_issued
from gateway.inbound.injection import check_injection
from gateway.inbound.judge import judge
from gateway.inbound.masker import inspect_inbound
from gateway.inbound.signatures import match_signatures
from gateway.models import (
    AuditRecord,
    ChatRequest,
    ChatResponse,
    IssuedCache,
    Policy,
    SignatureFeed,
    Verdict,
)
from gateway.outbound.fill import fill
from gateway.outbound.output_filter import filter_output


def run_pipeline(
    api_key: str,
    req: ChatRequest,
    policy: Policy,
    feed: SignatureFeed,
    cache: IssuedCache,
) -> tuple[ChatResponse, Verdict]:
    """Run one request through the 10 steps. Spec section 4.

    ``policy`` and ``feed`` are the snapshot taken at the start of the request and
    are used unchanged until the end (I14).
    """
    # TODO(step 1): Authenticate. Unknown key -> 401. Spec section 4 step 1, I2.
    p = authenticate(api_key, policy)

    # TODO(step 2): Model allowlist + budget pre-check; estimate tokens. Spec section 4 step 2, I11.
    estimate = 0
    check_model_and_budget(p, req.model, estimate, policy)

    # TODO(step 3): Inbound inspection: mask messages and tool results, re-mask
    # history, scan tool definitions. Spec section 4 step 3.
    sanitized, vault, decisions = inspect_inbound(req, p, policy, cache)

    # TODO(step 4): Input checks on the newest user message and new tool results:
    # injection phrases, signature feed, then judge. Spec section 4 step 4.
    newest = ""
    check_injection(newest, policy)
    match_signatures(newest, "user", feed)
    judge(newest, policy)

    # TODO(steps 5-6): Call the model and run the bounded query_data tool loop.
    # Spec section 4 steps 5-6, I7, I11.
    loop = run_tool_loop(sanitized, p, vault, policy)

    # TODO(step 7): Authorize each client tool call; drop denied ones. Spec section 4 step 7.
    tool_decisions = [authorize_tool_call(c, p, loop.bindings, policy) for c in loop.tool_calls]

    # TODO(step 8): Outbound fill, single literal pass. Spec section 4 step 8, I9.
    filled = fill(loop.text or "", loop.bindings, vault, policy)

    # TODO(step 9): Output filter on the answer and on allowed tool-call arguments.
    # Spec section 4 step 9, I10.
    answer, out_decision = filter_output(filled, p, policy)

    # TODO(step 10): Record usage and issued values, write exactly one audit record
    # (also for 401s, blocks and crashes), return an OpenAI-format response.
    # Spec section 4 step 10, I12.
    record_usage(p, loop.prompt_tokens + loop.completion_tokens, req.model, policy)
    record_issued(p, loop.bindings, cache)
    write_audit(
        AuditRecord(
            request_id="",
            timestamp="",
            policy_version=policy.version_hash,
            feed_version=feed.version,
            verdict=out_decision.verdict,
        )
    )
    raise NotImplementedError
