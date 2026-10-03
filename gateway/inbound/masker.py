"""Secrets + PII -> mask tokens, vault. Spec section 4 step 3. Owner: Person 2."""
from __future__ import annotations

from gateway.models import (
    ChatRequest,
    Decision,
    IssuedCache,
    Policy,
    Principal,
    SanitizedRequest,
    Vault,
)


def inspect_inbound(
    req: ChatRequest, p: Principal, policy: Policy, cache: IssuedCache
) -> tuple[SanitizedRequest, Vault, list[Decision]]:
    """Mask user messages and tool results, re-mask history, scan tool definitions. Spec section 4 step 3a-3d."""
    raise NotImplementedError
