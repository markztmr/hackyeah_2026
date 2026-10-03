"""Final checks on text and tool args. Spec section 4 step 9. Owner: Person 2."""
from __future__ import annotations

from gateway.models import Decision, FilledText, Policy, Principal


def filter_output(f: FilledText, p: Principal, policy: Policy) -> tuple[str, Decision]:
    """Check model-written spans; escape gateway-inserted spans; redact or block. Spec section 4 step 9, I10."""
    raise NotImplementedError
