"""Feed loading and matching per surface. Spec section 4 step 4, section 9. Owner: Person 2."""
from __future__ import annotations

from gateway.models import Decision, SignatureFeed


def match_signatures(text: str, surface: str, feed: SignatureFeed) -> Decision:
    """Match text against feed entries that apply to this surface. Spec section 4 step 4, section 9."""
    raise NotImplementedError
