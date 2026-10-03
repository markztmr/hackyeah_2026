"""Parse, SELECT only, functions, params. Spec section 5 'Validate'. Owner: Person 3."""
from __future__ import annotations

from gateway.models import Binding, Policy


def validate_sql(b: Binding, policy: Policy) -> Binding:
    """Parse with sqlglot; set status rejected or pass the binding on. Spec section 5 'Validate', I3, I5."""
    raise NotImplementedError
