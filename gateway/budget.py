"""Check and record usage (state.db). Spec section 4 steps 2 and 10, section 6 (budgets). Owner: Person 4.

Model allowlist part by Person 1. Digest pinning (Tier 2) is not implemented yet.
"""
from __future__ import annotations

import time

from gateway.models import Decision, Policy, Principal
from gateway.policy.loader import setting

STAGE = "model_and_budget"


def resolve_model(model: str, policy: Policy) -> tuple[str | None, Decision]:
    """The model to call for this request, or None if blocked. Spec section 4 step 2.

    Exact name match against ``models.allowed``. Unlisted: block, or substitute
    ``models.answer`` per ``models.on_unlisted`` (only if that model is itself allowed).
    Reasons never repeat the requested name: it is client input.
    """
    start = time.perf_counter()

    def decision(verdict: str, reason: str) -> Decision:
        return Decision(STAGE, "models.allowed", verdict, reason, (time.perf_counter() - start) * 1000)  # type: ignore[arg-type]

    try:
        allowed = {m["name"] for m in setting(policy, "models.allowed")}
        if model in allowed:
            return model, decision("allow", "Requested model is allowed.")
        answer = setting(policy, "models.answer.name")
        if setting(policy, "models.on_unlisted") == "substitute" and answer in allowed:
            return answer, decision("log", f"Requested model is not allowed; using {answer} instead.")
        return None, decision("block", "Requested model is not allowed by policy.")
    except Exception:  # noqa: BLE001 - a failing check denies (I6)
        return None, decision("block", "Model allowlist check failed.")


def check_model_and_budget(p: Principal, model: str, estimate: int, policy: Policy) -> Decision:
    """Model allowlist and budget pre-check before any model call. Spec section 4 step 2, I11."""
    resolved, decision = resolve_model(model, policy)
    if resolved is None:
        return decision
    # TODO(Person 4): tokens per day, requests per minute, cost per day (state.db).
    # Raises instead of allowing so that no request runs with the budget unchecked.
    raise NotImplementedError


def cost_usd(model: str, tokens: int, policy: Policy) -> float:
    """Notional cost from ``pricing_per_1k_tokens``; an unpriced model costs 0."""
    price = setting(policy, "pricing_per_1k_tokens").get(model, 0.0)
    return round(float(price) * tokens / 1000, 6)


def record_usage(p: Principal, tokens: int, model: str, policy: Policy) -> None:
    """Add actual token usage and cost to the budget store. Spec section 4 step 10."""
    raise NotImplementedError
