"""Final checks on text and tool args. Spec section 4 step 9, I15. Owner: Person 2.

Implemented by Person 1. Only model-written text is checked; gateway-inserted
spans (values from authorized bindings, the user's own restored input, markers)
are authorized by construction and never changed. Text not covered by any span
counts as model-written (deny by default).

On model-written text (and on any match in the filled text that includes a model-written
character, so text split around an inserted value is still caught):
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


def _findings(f: FilledText, segments: list[tuple[int, int]]) -> list[tuple[int, int, str]]:
    """Sensitive matches to redact, in ``f.text`` positions, merged where they overlap.

    Each model segment is checked on its own, and the whole filled text is checked too: a
    match that includes any model-written character counts, so text split around an
    inserted value (``attacker{x1}@evil.com``) cannot hide from the detectors. A match
    entirely inside gateway-inserted text is authorized and kept.
    """
    found: list[tuple[int, int, str]] = []
    for a, b in segments:
        found += [(a + s, a + e, kind) for s, e, kind in find_sensitive(f.text[a:b])]
    found += [(s, e, kind) for s, e, kind in find_sensitive(f.text)
              if any(s < b and a < e for a, b in segments)]
    merged: list[tuple[int, int, str]] = []
    for s, e, kind in sorted(found):
        if merged and s < merged[-1][1]:
            ms, me, mk = merged[-1]
            merged[-1] = (ms, max(me, e), mk)
        else:
            merged.append((s, e, kind))
    return merged


def filter_output(f: FilledText, p: Principal, policy: Policy) -> tuple[str, Decision]:
    """Check model-written spans and leave gateway-inserted spans unchanged; redact or block. Spec section 4 step 9, I10."""
    start_t = time.perf_counter()
    mode = setting(policy, "output_controls.mode")
    marker = setting(policy, "markers.rejected")
    segments = _model_segments(f)
    findings = _findings(f, segments)
    found = [kind for _, _, kind in findings]
    leftovers = 0

    def plain(a: int, b: int) -> str:
        """Text between redactions: unbound placeholders in model-written parts become the marker."""
        nonlocal leftovers
        out, pos = [], a
        for sa, sb in segments:
            lo, hi = max(sa, a), min(sb, b)
            if lo >= hi:
                continue
            out.append(f.text[pos:lo])  # gateway-inserted: unchanged
            cleaned, n = PLACEHOLDER.subn(lambda _m: marker, f.text[lo:hi])
            leftovers += n
            out.append(cleaned)
            pos = hi
        out.append(f.text[pos:b])
        return "".join(out)

    parts: list[str] = []
    pos = 0
    for s, e, _ in findings:
        parts += [plain(pos, s), REDACTED]
        pos = e
    parts.append(plain(pos, len(f.text)))
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
