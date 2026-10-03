"""Semantic check via judge model. Spec section 4 step 4 and 'Judge model hardening'. Owner: Person 2."""
from __future__ import annotations

from gateway.models import Decision, Policy


def judge(text: str, policy: Policy) -> Decision:
    """Score text with the judge model; parse only the risk number. Spec section 4 'Judge model hardening', I7, I11."""
    raise NotImplementedError
