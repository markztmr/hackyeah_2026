"""Placeholder or value for the model. Spec section 5 'Disclosure rule'. Owner: Person 3.

The real value is shown, as ``{x1} = <value>``, only if all five hold; otherwise the
bare placeholder:

1. The status is ``resolved``. Non-resolved bindings always return the bare
   placeholder, so the model never learns why.
2. The user's effective AI data policy is ``allow`` (user setting capped by the
   role's ``max_ai_data_policy``).
3. The binding's label is at or below the role's ``max_label_to_model``.
4. The receiving model's trust is ``local``, or the label is not ``sensitive``.
5. The value passes the injection and signature scan (database content is untrusted),
   on surface ``tool_result``.

The failed condition is recorded in ``binding.reason`` for the audit log; the tool
result is the same bare placeholder whatever failed (I14). Any error fails closed.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from gateway.inbound.injection import check_injection
from gateway.inbound.signatures import match_signatures, parse_feed
from gateway.models import Binding, ModelTrust, Policy, Principal, SignatureFeed
from gateway.policy.loader import policy_path, setting

_RANK = {"public": 0, "internal": 1, "sensitive": 2}
_SHOWN_TYPES = (str, int, float)  # what the executor produces; anything else stays hidden


def _role(p: Principal, policy: Policy) -> Mapping[str, Any] | None:
    role = (policy.tree.get("roles") or {}).get(p.role)
    return role if isinstance(role, Mapping) else None


def _feed(policy: Policy) -> SignatureFeed:
    """The feed named by ``prompt_controls.signatures.feed``, relative to the policy file.

    Read fresh each time: an unreadable or invalid file raises, and disclosure then fails closed.
    """
    path = Path(setting(policy, "prompt_controls.signatures.feed"))
    if not path.is_absolute():
        path = policy_path().parent / path
    return parse_feed(path.read_bytes())


def _withheld(b: Binding, p: Principal, policy: Policy, trust: ModelTrust) -> str | None:
    """Why the value is not shown (conditions 2-5), or None if it may be."""
    role = _role(p, policy)
    if role is None:
        return "role has no disclosure limits"
    if p.ai_data_policy != "allow" or role.get("max_ai_data_policy") != "allow":
        return "the user's AI data policy is deny"
    label, limit = b.label, role.get("max_label_to_model")
    if label not in _RANK or limit not in _RANK:
        return "the label is unknown"
    if _RANK[label] > _RANK[limit]:
        return "label " + label + " is above the role's limit " + limit
    if trust != "local" and label == "sensitive":
        return "the value is sensitive and the answer model is external"
    if isinstance(b.value, bool) or not isinstance(b.value, _SHOWN_TYPES):
        return "the value has an unsupported type"
    value = str(b.value)
    if check_injection(value, policy).verdict != "allow":
        return "the value matches an injection phrase"
    if match_signatures(value, "tool_result", _feed(policy), policy).verdict != "allow":
        return "the value matches an attack signature"
    return None


def disclose(b: Binding, p: Principal, policy: Policy, *, trust: ModelTrust = "external") -> str:
    """Tool result for the model: bare placeholder unless the disclosure rule allows the value. Spec section 5, I7, I10.

    ``trust`` is the trust of the model that will receive the result (rule 4: an
    external model never gets a sensitive value). The tool loop passes it; when
    omitted it takes the restrictive value.
    """
    b.disclosed = False
    if b.status != "resolved":  # condition 1; the binding already carries why
        return b.name
    try:
        why = _withheld(b, p, policy, trust)
    except Exception:  # noqa: BLE001 - deny by default (I6)
        why = "the disclosure check failed"
    if why is not None:
        note = "Not disclosed to the model: " + why + "."
        b.reason = (b.reason + " " + note).strip()
        return b.name
    b.disclosed = True
    return b.name + " = " + str(b.value)
