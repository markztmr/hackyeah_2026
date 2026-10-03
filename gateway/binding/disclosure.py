"""Placeholder or value for the model. Spec section 5 'Disclosure rule'. Owner: Person 3.

MVP (Tier 1): nothing is ever disclosed. The model always receives the bare
placeholder and ``disclosed`` is False, whatever the status, user, label, model
trust or policy. This is the strictest form of I7 and gives I14 for free: every
outcome looks the same to the model.

Planned T2 behaviour (spec section 5). The real value is shown, as
``{x1} = <value>``, only if all five hold; otherwise the bare placeholder:

1. The status is ``resolved``. Non-resolved bindings always return the bare
   placeholder, so the model never learns why.
2. The user's effective AI data policy is ``allow`` (user setting capped by the
   role's ``max_ai_data_policy``).
3. The binding's label is at or below the role's ``max_label_to_model``.
4. The receiving model's trust is ``local``, or the label is not ``sensitive``.
5. The value passes the injection and signature scan (database content is untrusted).
"""
from __future__ import annotations

from gateway.models import Binding, ModelTrust, Policy, Principal


def disclose(b: Binding, p: Principal, policy: Policy, *, trust: ModelTrust = "external") -> str:
    """Tool result for the model: bare placeholder unless the disclosure rule allows the value. Spec section 5, I7.

    ``trust`` is the trust of the model that will receive the result (rule 4: an
    external model never gets a sensitive value). The tool loop passes it; when
    omitted it takes the restrictive value. MVP: always the bare placeholder.
    """
    b.disclosed = False
    return b.name
