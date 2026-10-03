"""Tables, columns, scope, literal identity. Spec section 5 'Authorize'. Owner: Person 3."""
from __future__ import annotations

from gateway.models import Binding, Policy, Principal


def authorize(b: Binding, p: Principal, policy: Policy) -> Binding:
    """Check tables, columns and scope for the role; set status denied or pass. Spec section 5 'Authorize', I6."""
    raise NotImplementedError
