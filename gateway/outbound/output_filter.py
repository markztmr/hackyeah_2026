"""Final checks on text and tool args. Spec section 4 step 9, I15. Owner: Person 2.

Implemented by Person 1. Only model-written text is checked; gateway-inserted
spans (values from authorized bindings, the user's own restored input, markers)
are authorized by construction and never changed. Text not covered by any span
counts as model-written (deny by default).

On model-written text:
- secrets and PII (same detectors and checksums as the inbound masker). The user's
  own input reaches the answer only as a gateway-inserted span via
  ``echo_own_input``, so PII written by the model is PII the user did not supply;
- leftover ``{x<n>}`` placeholders become the ``rejected`` marker.

``output_controls.mode``: ``redact`` replaces findings with ``[REDACTED]``; ``block``
blocks the answer. Leftover placeholders are always just replaced.
Guessed protected values (protected-value index) are Tier 2 and not checked yet.
"""
from __future__ import annotations

import re
import time

from gateway.inbound.masker import find_sensitive
from gateway.models import Decision, FilledText, Policy, Principal
from gateway.policy.loader import setting

REDACTED = "[REDACTED]"
PLACEHOLDER = re.compile(r"\{x\d+\}")
STAGE, CONTROL = "output_filter", "output_controls"


def _model_segments(f: FilledText) -> list[tuple[int, int]]:
    """Ranges of ``f.text`` not covered by a gateway-inserted span."""
    gateway = sorted((s.start, s.end) for s in f.spans if s.source == "gateway")
    segments, pos = [], 0
    for start, end in gateway:
        if start > pos:
            segments.append((pos, start))
        pos = max(pos, end)
    if pos < len(f.text):
        segments.append((pos, len(f.text)))
    return segments


def filter_output(f: FilledText, p: Principal, policy: Policy) -> tuple[str, Decision]:
    """Check model-written spans and leave gateway-inserted spans unchanged; redact or block. Spec section 4 step 9, I10."""
    start_t = time.perf_counter()
    mode = setting(policy, "output_controls.mode")
    marker = setting(policy, "markers.rejected")
    found: list[str] = []
    leftovers = 0
    parts: list[str] = []
    pos = 0
    for seg_start, seg_end in _model_segments(f):
        parts.append(f.text[pos:seg_start])  # gateway-inserted: unchanged
        segment = f.text[seg_start:seg_end]
        out, cursor = [], 0
        for s, e, kind in find_sensitive(segment):
            found.append(kind)
            out += [segment[cursor:s], REDACTED]
            cursor = e
        out.append(segment[cursor:])
        cleaned, n = PLACEHOLDER.subn(lambda _m: marker, "".join(out))
        leftovers += n
        parts.append(cleaned)
        pos = seg_end
    parts.append(f.text[pos:])
    ms = (time.perf_counter() - start_t) * 1000

    if found and mode == "block":
        types = ", ".join(sorted(set(found)))
        return "", Decision(STAGE, CONTROL, "block", f"The answer contained sensitive data ({types}).", ms)
    text = "".join(parts)
    if not found and not leftovers:
        return text, Decision(STAGE, CONTROL, "allow", "", ms)
    reasons = []
    if found:
        reasons.append(f"Redacted {len(found)} value(s) the model wrote ({', '.join(sorted(set(found)))}).")
    if leftovers:
        reasons.append(f"Replaced {leftovers} unbound placeholder(s).")
    return text, Decision(STAGE, CONTROL, "redact", " ".join(reasons), ms)
