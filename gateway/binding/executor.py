"""Read-only connection, set_authorizer, limits. The only module that opens the database (I1). Spec section 5 'Execute'. Owner: Person 3."""
from __future__ import annotations

from gateway.models import Binding, Policy, Principal


def execute(b: Binding, p: Principal, policy: Policy) -> Binding:
    """Run exactly the validated SQL on a read-only connection; resolved, empty or error. Spec section 5 'Execute', I1, I4."""
    raise NotImplementedError
