"""Single-pass literal fill, spans. Spec section 4 step 8, section 5 'Placeholder rules'. Owner: Person 3.

Implemented by Person 1. One ``re.sub`` pass with a replacement function over the
model's text (I13, CLAUDE.md rule 9): no ``str.format``, f-strings, ``%`` or
templates anywhere in this module, and inserted text is never scanned again.

- ``{x<n>}`` with a resolved binding -> its value, escaped per ``output_controls.escape``.
  A ``list`` value is already a markdown table whose cells the executor escaped,
  so it is inserted as it is.
- ``{x<n>}`` with any other status -> ``markers.<status>``; strict uses one marker for all.
- ``{x<n>}`` with no binding (or no finished outcome) -> the unavailable marker
  (``markers.rejected``, the marker the output filter also uses).
- ``[TYPE_n]`` mask tokens the user typed are restored from the vault only if
  ``output_controls.echo_own_input`` is true, escaped like values.
- If ``markers.all_denied_message`` is set, the text contains a placeholder and no
  binding resolved, the whole text becomes that message.

Every replacement is a ``gateway`` span; the text between them is ``model`` spans.
The output filter checks only the model spans.
"""
from __future__ import annotations

import re

from gateway.models import Binding, FilledText, Policy, Span, Vault
from gateway.policy.loader import setting

_TOKEN = re.compile(r"\{x(\d+)\}|\[[A-Z]+_\d+\]")
_MARKED = ("denied", "rejected", "empty", "error")
# Markdown punctuation is backslash-escaped; < > & become entities so no renderer sees a tag.
_MARKDOWN = str.maketrans({
    "\\": "\\\\", "`": "\\`", "*": "\\*", "_": "\\_", "[": "\\[", "]": "\\]", "|": "\\|",
    "~": "\\~", "#": "\\#", "<": "&lt;", ">": "&gt;", "&": "&amp;",
})


def escape_value(text: str, mode: str) -> str:
    """Escape inserted text for ``output_controls.escape`` (``markdown`` or ``none``)."""
    return text if mode == "none" else text.translate(_MARKDOWN)


def _as_text(value: object) -> str:
    return value if isinstance(value, str) else str(value)


def fill(text: str, bindings: dict[str, Binding], vault: Vault, policy: Policy) -> FilledText:
    """Replace placeholders with values or markers in one literal pass. Spec section 5 'Placeholder rules', I9."""
    mode = setting(policy, "output_controls.escape")
    echo = bool(setting(policy, "output_controls.echo_own_input"))
    unavailable = setting(policy, "markers.rejected")
    markers = {status: setting(policy, "markers." + status) for status in _MARKED}
    inserted: list[Span] = []
    shift = 0  # output offset minus input offset, up to the current match
    placeholders = 0

    def replace(m: re.Match[str]) -> str:
        nonlocal shift, placeholders
        token = m.group(0)
        binding_name: str | None = None
        if m.group(1) is not None:
            placeholders += 1
            b = bindings.get(token)
            if b is not None and b.status == "resolved" and b.value is not None:
                value = _as_text(b.value)
                out = value if b.expect == "list" else escape_value(value, mode)
                binding_name = token
            elif b is not None and b.status in markers:
                out, binding_name = markers[b.status], token
            else:
                out = unavailable
        else:
            original = vault.mask(token) if echo else None
            if original is None:
                return token  # stays model text
            out = escape_value(original, mode)
        start = m.start() + shift
        inserted.append(Span(start, start + len(out), "gateway", binding_name))
        shift += len(out) - len(token)
        return out

    result = _TOKEN.sub(replace, text)

    message = setting(policy, "markers.all_denied_message")
    if message and placeholders and bindings and not any(b.status == "resolved" for b in bindings.values()):
        return FilledText(text=message, spans=[Span(0, len(message), "gateway")])

    spans: list[Span] = []
    pos = 0
    for s in inserted:
        if s.start > pos:
            spans.append(Span(pos, s.start, "model"))
        spans.append(s)
        pos = s.end
    if pos < len(result):
        spans.append(Span(pos, len(result), "model"))
    return FilledText(text=result, spans=spans)
