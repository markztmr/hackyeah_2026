"""History re-masking, issued-value cache. Spec section 4 steps 3c and 10. Owner: Person 2."""
from __future__ import annotations

from gateway.models import Binding, IssuedCache, Principal


def record_issued(p: Principal, bindings: dict[str, Binding], cache: IssuedCache) -> None:
    """Remember hidden values inserted in this answer for history re-masking. Spec section 4 step 10."""
    raise NotImplementedError
