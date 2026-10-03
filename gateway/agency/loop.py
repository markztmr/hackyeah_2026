"""Tool loop, mixed-turn rule, limits. Spec section 4 steps 5-6. Owner: Person 1."""
from __future__ import annotations

from gateway.models import LoopResult, Policy, Principal, SanitizedRequest, Vault


def run_tool_loop(req: SanitizedRequest, p: Principal, vault: Vault, policy: Policy) -> LoopResult:
    """Call the model and resolve query_data calls until final text or client tool calls. Spec section 4 steps 5-6."""
    raise NotImplementedError
