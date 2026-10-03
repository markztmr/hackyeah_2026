"""Check and record usage (state.db). Spec section 4 steps 2 and 10, section 6 (budgets). Owner: Person 4."""
from __future__ import annotations

from gateway.models import Decision, Policy, Principal


def check_model_and_budget(p: Principal, model: str, estimate: int, policy: Policy) -> Decision:
    """Model allowlist and budget pre-check before any model call. Spec section 4 step 2, I11."""
    raise NotImplementedError


def record_usage(p: Principal, tokens: int, model: str, policy: Policy) -> None:
    """Add actual token usage and cost to the budget store. Spec section 4 step 10."""
    raise NotImplementedError
