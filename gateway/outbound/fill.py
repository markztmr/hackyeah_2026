"""Single-pass literal fill, spans. Spec section 4 step 8, section 5 'Placeholder rules'. Owner: Person 3."""
from __future__ import annotations

from gateway.models import Binding, FilledText, Policy, Vault


def fill(text: str, bindings: dict[str, Binding], vault: Vault, policy: Policy) -> FilledText:
    """Replace placeholders with values or markers in one literal pass. Spec section 5 'Placeholder rules', I9."""
    raise NotImplementedError
