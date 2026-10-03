"""Placeholder or value for the model. Spec section 5 'Disclosure rule'. Owner: Person 3."""
from __future__ import annotations

from gateway.models import Binding, ModelTrust, Policy, Principal


def disclose(b: Binding, p: Principal, policy: Policy, *, trust: ModelTrust) -> str:
    """Tool result for the model: bare placeholder unless the disclosure rule allows the value. Spec section 5, I7.

    ``trust`` is the trust of the model that will receive the result (rule 4: an
    external model never gets a sensitive value). The tool loop passes it.
    """
    raise NotImplementedError
