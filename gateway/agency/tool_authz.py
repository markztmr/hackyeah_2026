"""Client tool rules, argument rules, egress. Spec section 4 step 7, section 5. Owner: Person 3.

Implemented by Person 1. Checks, in order; the first failure denies the whole call (I6, I11):

1. ``not_listed``: the role lists the tool, by exact name.
2. ``malformed_arguments``: the arguments are a JSON object (the loop passes the raw
   string through when they are not).
3. Argument rules from ``roles.<role>.tools.<tool>.args``:
   - ``argument_name``: an argument whose name differs from a ruled argument only by case
     or punctuation (``To`` next to a rule on ``to``) is denied, so a rule cannot be dodged;
   - ``allow_pattern``: the argument must be present, a string, and match the whole
     pattern (``re.fullmatch``, so ``$`` cannot match before a trailing newline);
   - ``deny_pattern``: if present, the argument must be a string the pattern does not find;
   - ``max``: if present, the argument must be a finite number (not a bool) at most ``max``.
4. ``egress``: placeholders anywhere in the arguments (keys included) may be filled only
   if the tool has ``max_label`` and every placeholder's binding resolved with a label at
   or below it. No ``max_label`` means ``tool_controls.placeholder_egress: deny``. A
   non-resolved or unknown placeholder denies: the call is never sent with a marker.

Reasons name the tool and the policy's argument names only, never argument values (I8).
The pipeline removes denied calls and fills the allowed ones (step 8).
"""
from __future__ import annotations

import math
import re
import unicodedata
from collections.abc import Iterator, Mapping
from typing import Any

from gateway.inbound.injection import safe_tool_label
from gateway.models import Binding, Policy, Principal, ToolCall, ToolDecision

PLACEHOLDER = re.compile(r"\{x\d+\}")
_RANK = {"public": 0, "internal": 1, "sensitive": 2}
_MISSING = object()


def _norm(name: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKC", name).casefold() if c.isalnum())


def _strings(value: Any) -> Iterator[str]:
    """Every key and string leaf in a JSON value, without recursion."""
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            yield v
        elif isinstance(v, Mapping):
            stack.extend(str(k) for k in v)
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)


def _value_texts(value: object) -> set[str]:
    """How a disclosed value may be written: its text, and an integral float without '.0'."""
    texts = {value if isinstance(value, str) else str(value)}
    if isinstance(value, float) and value.is_integer():
        texts.add(str(int(value)))
    return {t.strip() for t in texts if t.strip()}


def _copied_disclosed_values(args: Any, bindings: dict[str, Binding]) -> set[str]:
    """Names of disclosed bindings whose value appears as a token in the arguments (keys,
    strings and numbers). Matching is case-insensitive and bounded by non-alphanumerics."""
    disclosed = [b for b in bindings.values() if b.disclosed and b.value is not None]
    if not disclosed:
        return set()
    texts = list(_strings(args))
    stack: list[Any] = [args]
    while stack:  # numbers are text the model wrote too
        v = stack.pop()
        if isinstance(v, Mapping):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            texts.append(str(v))
    found: set[str] = set()
    for b in disclosed:
        for t in _value_texts(b.value):
            pattern = re.compile(r"(?<![0-9A-Za-z])" + re.escape(t) + r"(?![0-9A-Za-z])", re.IGNORECASE)
            if any(pattern.search(x) for x in texts):
                found.add(b.name)
    return found


def _rule_failure(arg: str, rule: Mapping[str, Any], value: Any) -> str | None:
    """The name of the first rule this argument value fails, or None."""
    if "allow_pattern" in rule and (
            not isinstance(value, str) or re.fullmatch(rule["allow_pattern"], value) is None):
        return "allow_pattern"
    if "deny_pattern" in rule and value is not _MISSING and (
            not isinstance(value, str) or re.search(rule["deny_pattern"], value) is not None):
        return "deny_pattern"
    if "max" in rule and value is not _MISSING and (
            isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value > rule["max"]):
        return "max"
    return None


def policy_approved_arguments(call: ToolCall, p: Principal, policy: Policy) -> frozenset[str]:
    """Top-level arguments whose whole value matches the policy's ``allow_pattern`` for this tool.

    The policy author approved exactly these values (a recipient inside the company), so the
    pipeline treats them as authorized spans: the output filter does not redact them as PII.
    The signature scan still covers them.
    """
    role = (policy.tree.get("roles") or {}).get(p.role)
    tool = ((role.get("tools") or {}) if isinstance(role, Mapping) else {}).get(call.name)
    if not isinstance(tool, Mapping) or not isinstance(call.arguments, dict):
        return frozenset()
    return frozenset(
        arg for arg, rule in (tool.get("args") or {}).items()
        if "allow_pattern" in rule and isinstance(call.arguments.get(arg), str)
        and not PLACEHOLDER.search(call.arguments[arg])  # approved text only, never a filled value
        and re.fullmatch(rule["allow_pattern"], call.arguments[arg]) is not None
    )


def authorize_tool_call(
    call: ToolCall, p: Principal, bindings: dict[str, Binding], policy: Policy
) -> ToolDecision:
    """Role tool list, argument rules and placeholder egress. Spec section 5 'Client tool authorization'."""
    role = (policy.tree.get("roles") or {}).get(p.role)
    tools: Mapping[str, Any] = (role.get("tools") or {}) if isinstance(role, Mapping) else {}
    name = call.name
    tool = tools.get(name) if isinstance(name, str) else None
    if not isinstance(tool, Mapping):
        label = safe_tool_label(name, 0)
        return ToolDecision(label, "deny", "not_listed", f"Tool {label} is not allowed for role {p.role}.")

    args = call.arguments
    if not isinstance(args, dict):
        return ToolDecision(name, "deny", "malformed_arguments", f"Arguments of {name} are not a JSON object.")

    rules: Mapping[str, Any] = tool.get("args") or {}
    ruled = {_norm(k): k for k in rules}
    for key in args:
        target = ruled.get(_norm(str(key)))
        if target is not None and key != target:
            return ToolDecision(name, "deny", "argument_name",
                                f"An argument of {name} imitates the ruled argument '{target}'.")
    for arg, rule in rules.items():
        value = args.get(arg, _MISSING)
        # A rule judges the text that is sent. Fill runs after this check, so a placeholder
        # inside a ruled argument would let a database value dodge the rule.
        if value is not _MISSING and any(PLACEHOLDER.search(t) for t in _strings(value)):
            return ToolDecision(name, "deny", "egress",
                                f"Argument '{arg}' of {name} has a rule and may not carry query results.")
        failed = _rule_failure(arg, rule, value)
        if failed is not None:
            return ToolDecision(name, "deny", failed, f"Argument '{arg}' of {name} breaks its {failed} rule.")

    placeholders = {m.group(0) for s in _strings(args) for m in PLACEHOLDER.finditer(s)}
    # A value already disclosed to the model ("{x1} = ...") can be copied literally;
    # it is egress of that binding just like its placeholder.
    placeholders |= _copied_disclosed_values(args, bindings)
    if placeholders:
        max_label = tool.get("max_label")
        if max_label not in _RANK:
            return ToolDecision(name, "deny", "egress",
                                f"{name} may not carry query results (no max_label; placeholder egress is denied).")
        for ph in placeholders:
            b = bindings.get(ph)
            if b is None or b.status != "resolved" or b.label not in _RANK or _RANK[b.label] > _RANK[max_label]:
                return ToolDecision(name, "deny", "egress",
                                    f"{name} may carry values up to label {max_label} only.")
    return ToolDecision(name, "allow", "role", f"{name} is allowed for role {p.role}.")
