"""API key -> Principal. Spec section 4 step 1, section 6 (Principals), section 13. Owner: Person 1.

Identity comes only from the API key (I2): this module never sees messages.
"""
from __future__ import annotations

import hmac

from gateway.models import AiDataPolicy, Policy, Principal
from gateway.policy.loader import setting


class AuthError(Exception):
    """Unknown or missing API key. main.py returns 401. Never carries the key (I8)."""

    def __init__(self) -> None:
        super().__init__("Invalid or missing API key.")


def _cap(user: AiDataPolicy, role_max: AiDataPolicy) -> AiDataPolicy:
    """The user's setting capped by the role maximum: allow only if both allow."""
    return "allow" if user == "allow" and role_max == "allow" else "deny"


def authenticate(api_key: str, policy: Policy) -> Principal:
    """Resolve the API key to a Principal; unknown key fails. Spec section 4 step 1, I2."""
    if not isinstance(api_key, str) or not api_key:
        raise AuthError()
    try:
        supplied = api_key.encode("utf-8")
        match: str | None = None
        users = setting(policy, "users")
        # Compare against every key, without stopping at the first match.
        for user_id, user in users.items():
            if hmac.compare_digest(supplied, user["api_key"].encode("utf-8")):
                match = user_id
        if match is None:
            raise AuthError()
        user = users[match]
        role = setting(policy, "roles")[user["role"]]
        return Principal(
            user_id=match,
            role=user["role"],
            department=user["department"],
            ai_data_policy=_cap(user["ai_data_policy"], role["max_ai_data_policy"]),
        )
    except AuthError:
        raise
    except Exception:  # noqa: BLE001 - any failure in the check denies (I6)
        raise AuthError() from None
