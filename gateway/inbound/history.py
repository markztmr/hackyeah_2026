"""History re-masking, issued-value cache. Spec section 4 steps 3c and 10, I9. Owner: Person 2.

Step 10 (``record_issued``): every resolved binding that was NOT disclosed to the model
had its value filled into the answer by the gateway. Its formatted text (as fill
inserts it, raw and markdown-escaped) is remembered per user in the in-memory
``IssuedCache``.

Step 3c (``remask_history``): when that user's client sends the answer back as history,
exact whole occurrences in assistant messages (content and tool-call arguments) become
``markers.prior_value``, so the model never sees the value in a later turn. Entries
expire after ``prompt_controls.history_remask.ttl_minutes``. A value the user retypes,
in a user message or in other formatting, is the user's own disclosure (I9).

Values are never logged; only counts leave this module.
"""
from __future__ import annotations

import re
import time
from typing import Any

from gateway.models import Binding, IssuedCache, Policy, Principal
from gateway.outbound.fill import escape_value
from gateway.policy.loader import setting

# A value matches only as a whole: no letter or digit right before or after it, and a
# number is not the start of a longer one ("6200" is not inside "16200" or "6200.5").
_BEFORE = r"(?<![^\W_])(?<!\d[.,])"
_AFTER = r"(?![^\W_])(?![.,]\d)"


def _now() -> float:
    return time.time()


def _forms(b: Binding) -> set[str]:
    """The text fill inserts for this binding: raw for lists (already escaped cells), else raw and markdown-escaped."""
    text = b.value if isinstance(b.value, str) else str(b.value)
    return {text} if b.expect == "list" else {text, escape_value(text, "markdown")}


def record_issued(p: Principal, bindings: dict[str, Binding], cache: IssuedCache, *, now: float | None = None) -> None:
    """Remember hidden values inserted in this answer for history re-masking. Spec section 4 step 10."""
    at = _now() if now is None else now
    for b in bindings.values():
        if b.status != "resolved" or b.disclosed or b.value is None:
            continue
        for form in _forms(b):
            if form.strip():
                cache.add(p.user_id, form, at)


def _pattern(values: list[str]) -> re.Pattern[str]:
    alternatives = "|".join(re.escape(v) for v in sorted(values, key=len, reverse=True))  # longest first
    return re.compile(_BEFORE + "(?:" + alternatives + ")" + _AFTER)


def remask_history(
    messages: list[dict[str, Any]], p: Principal, cache: IssuedCache, policy: Policy, *, now: float | None = None
) -> tuple[list[dict[str, Any]], int]:
    """Replace this user's live issued values in assistant messages with ``markers.prior_value``. Spec section 4 step 3c.

    Returns new messages (the input is not changed) and the number of replacements.
    """
    if not setting(policy, "prompt_controls.history_remask.enabled"):
        return messages, 0
    ttl_s = float(setting(policy, "prompt_controls.history_remask.ttl_minutes")) * 60
    values = cache.live_values(p.user_id, (_now() if now is None else now) - ttl_s)
    if not values:
        return messages, 0
    pattern, marker = _pattern(values), str(setting(policy, "markers.prior_value"))
    count = 0

    def sub(text: Any) -> Any:
        nonlocal count
        if not isinstance(text, str):
            return text
        new, n = pattern.subn(lambda _m: marker, text)  # a function: the marker is inserted literally
        count += n
        return new

    out: list[dict[str, Any]] = []
    for m in messages:
        if m.get("role") != "assistant":
            out.append(m)
            continue
        m = dict(m)
        content = m.get("content")
        if isinstance(content, list):
            m["content"] = [{**part, "text": sub(part["text"])} if isinstance(part, dict) and "text" in part else part
                            for part in content]
        else:
            m["content"] = sub(content)
        if isinstance(m.get("tool_calls"), list):
            calls = []
            for c in m["tool_calls"]:
                fn = c.get("function") if isinstance(c, dict) else None
                if isinstance(fn, dict) and "arguments" in fn:
                    c = {**c, "function": {**fn, "arguments": sub(fn["arguments"])}}
                calls.append(c)
            m["tool_calls"] = calls
        out.append(m)
    return out, count
