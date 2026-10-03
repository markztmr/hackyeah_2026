"""Placeholder or value for the model. Spec section 5 'Disclosure rule'. Owner: Person 3."""
from __future__ import annotations

from gateway.models import Binding, Policy, Principal


def disclose(b: Binding, p: Principal, policy: Policy) -> str:
    """Tool result for the model: bare placeholder unless the disclosure rule allows the value. Spec section 5, I7."""
    raise NotImplementedError
