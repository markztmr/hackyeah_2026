"""API key -> Principal. Spec section 4 step 1, section 6 (Principals), section 13. Owner: Person 1."""
from __future__ import annotations

from gateway.models import Policy, Principal


def authenticate(api_key: str, policy: Policy) -> Principal:
    """Resolve the API key to a Principal; unknown key fails. Spec section 4 step 1, I2."""
    raise NotImplementedError
