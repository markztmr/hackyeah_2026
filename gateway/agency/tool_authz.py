"""Client tool rules, argument rules, egress. Spec section 4 step 7, section 5. Owner: Person 3."""
from __future__ import annotations

from gateway.models import Binding, Policy, Principal, ToolCall, ToolDecision


def authorize_tool_call(
    call: ToolCall, p: Principal, bindings: dict[str, Binding], policy: Policy
) -> ToolDecision:
    """Role tool list, argument rules and placeholder egress. Spec section 5 'Client tool authorization'."""
    raise NotImplementedError
