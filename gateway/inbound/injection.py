"""Injection phrase list (EN + PL). Spec section 4 step 4. Owner: Person 2."""
from __future__ import annotations

from gateway.models import Decision, Policy


def check_injection(text: str, policy: Policy) -> Decision:
    """Match sanitized text against injection phrases. Spec section 4 step 4."""
    raise NotImplementedError
