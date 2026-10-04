"""Secrets + PII -> mask tokens, vault. Spec section 4 step 3a-3b, section 8 'Inbound stage'. Owner: Person 2.

``mask_messages`` by Person 1. Detection is deterministic: regexes find candidates,
and card numbers (Luhn), PESEL (checksum and date) and IBAN (mod-97) must also
validate, so ordinary numbers are not masked. Overlapping candidates are resolved
by priority, then every message is rewritten in one left-to-right pass.

Detection runs on a normalized view of the text (format characters such as
zero-width spaces removed, NFKC: full-width forms and no-break spaces folded,
dash variants folded), and every match is mapped back to the original span, so
Unicode tricks cannot hide a value (red-team RT-4).
"""
from __future__ import annotations

import copy
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gateway.models import (
    ChatRequest,
    Decision,
    Finding,
    IssuedCache,
    Policy,
    Principal,
    SanitizedRequest,
    SignatureFeed,
    Vault,
)
from gateway.inbound.signatures import FeedStore
from gateway.policy.loader import policy_path, setting

STAGE = "inbound"

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _digits(s: str) -> str:
    return re.sub(r"[ -]", "", s)


def _luhn(number: str) -> bool:
    """A card number: network first digit (2-6; 13 digits only Visa) and a valid Luhn checksum.

    The prefix rule stops Luhn-valid-by-chance numbers such as EAN-13 product codes.
    """
    d = _digits(number)
    if not 13 <= len(d) <= 19 or len(set(d)) == 1 or d[0] not in "23456" or (len(d) == 13 and d[0] != "4"):
        return False
    total = 0
    for i, c in enumerate(reversed(d)):
        x = int(c) * (2 if i % 2 else 1)
        total += x - 9 if x > 9 else x
    return total % 10 == 0


_PESEL_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)


def _pesel(number: str) -> bool:
    if len(number) != 11 or not number.isdigit():
        return False
    if (10 - sum(int(a) * w for a, w in zip(number, _PESEL_WEIGHTS)) % 10) % 10 != int(number[10]):
        return False
    month, day = int(number[2:4]) % 20, int(number[4:6])  # +20/+40/+60/+80 encode the century
    return 1 <= month <= 12 and 1 <= day <= 31


_IBAN_LENGTHS = {"PL": 28, "DE": 22, "GB": 22, "FR": 27, "ES": 24, "IT": 27, "NL": 18, "CZ": 24, "SK": 24}


def _iban(text: str) -> bool:
    s = text.replace(" ", "").upper()
    if not 15 <= len(s) <= 34 or _IBAN_LENGTHS.get(s[:2], len(s)) != len(s):
        return False
    rearranged = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1
    except ValueError:
        return False


def _nrb(text: str) -> bool:
    """Polish account number without the country code: valid as ``PL`` + number."""
    return _iban("PL" + _digits(text))


# ---------------------------------------------------------------------------
# Detectors, in priority order (a lower number wins an overlap)
# ---------------------------------------------------------------------------

# Digit runs: never start or end inside a longer run of digits and separators.
_NUM_START = r"(?<![\d+])(?<!\d[ -])"
_NUM_END = r"(?![ -]?\d)"
# Value of a credential assignment (password=..., "api_key": "..."): inside quotes only, so JSON stays
# valid when masked; a bare value must contain a non-letter or be 12+ characters ("token: expires" is prose).
_VALUE = (r"\s*[=:]\s*(?:\"([^\"\n]*)\"|'([^'\n]*)'"
          r"|((?=[^\s,;}'\"]*[^A-Za-z\s,;}'\"])[^\s,;}'\"]+|[^\s,;}'\"]{12,}))")


@dataclass(frozen=True, slots=True)
class _Detector:
    type: str
    control: str  # "secrets" or "pii"
    pattern: re.Pattern[str]
    priority: int
    group: tuple[int, ...] = (0,)  # the first group that took part in the match is the value
    valid: Callable[[str], bool] = field(default=lambda s: True)


_DETECTORS: tuple[_Detector, ...] = (
    _Detector("private_key", "secrets", re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)", re.S), 0),
    _Detector("jwt", "secrets", re.compile(
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), 0),
    # Real keys are long; short test keys ("sk-test123") count too when they contain a digit,
    # so words such as "sk-learn" stay plain text.
    _Detector("openai_key", "secrets", re.compile(
        r"(?<![A-Za-z0-9_-])sk-(?:[A-Za-z0-9_-]{20,}|(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{6,19}(?![A-Za-z0-9_-]))"), 0),
    _Detector("aws_key", "secrets", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"), 0),
    _Detector("github_token", "secrets", re.compile(
        r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})(?![A-Za-z0-9_])"), 0),
    _Detector("password", "secrets", re.compile(
        r"(?i)(?<![^\W\d_])[\"']?(?:password|passwd|pwd|pass|hasło|haslo)[\"']?" + _VALUE), 0, group=(1, 2, 3)),
    _Detector("api_secret", "secrets", re.compile(
        r"(?i)(?<![^\W\d_])[\"']?(?:client[_-]?secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token"
        r"|secret[_-]?key|private[_-]?key|secret|token)[\"']?" + _VALUE), 0, group=(1, 2, 3)),
    _Detector("bearer_token", "secrets", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)"), 0, group=(1,)),
    _Detector("stripe_key", "secrets", re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"), 0),
    _Detector("iban", "pii", re.compile(
        r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])"), 1, valid=_iban),
    _Detector("iban", "pii", re.compile(_NUM_START + r"\d{2}(?: ?\d{4}){6}" + _NUM_END), 1, valid=_nrb),
    _Detector("email", "pii", re.compile(
        r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![A-Za-z0-9-])"), 2),
    _Detector("phone", "pii", re.compile(
        r"(?<![\d+])(?:\+|00)48[ -]?(?:\d{3}[ -]?\d{3}[ -]?\d{3}|\d{2}[ -]?\d{3}[ -]?\d{2}[ -]?\d{2})" + _NUM_END), 3),
    _Detector("card", "pii", re.compile(_NUM_START + r"\d(?:[ -]?\d){12,18}" + _NUM_END), 4, valid=_luhn),
    _Detector("pesel", "pii", re.compile(_NUM_START + r"\d{11}" + _NUM_END), 5, valid=_pesel),
    _Detector("phone", "pii", re.compile(
        _NUM_START + r"(?:[1-9]\d{2}[ -]?\d{3}[ -]?\d{3}|[1-9]\d[ -]?\d{3}[ -]?\d{2}[ -]?\d{2})" + _NUM_END), 6),
)


_DASHES = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe63\uff0d"), "-")


def _view(text: str) -> tuple[str, list[int] | None]:
    """Normalized text for detection and, unless it is unchanged ASCII, the original index of each character."""
    if text.isascii():
        return text, None
    chars: list[str] = []
    index: list[int] = []
    for i, c in enumerate(text):
        if unicodedata.category(c) == "Cf":  # zero-width space, joiners, soft hyphen, bidi marks
            continue
        for n in unicodedata.normalize("NFKC", c).translate(_DASHES):
            chars.append(n)
            index.append(i)
    return "".join(chars), index


def _find(text: str, detectors: list[_Detector] | tuple[_Detector, ...]) -> list[tuple[int, int, _Detector]]:
    """Validated, non-overlapping matches as spans of the original ``text``, in order.

    Overlaps go to the higher-priority detector. Matching runs on ``_view(text)``.
    """
    view, index = _view(text)
    candidates: list[tuple[int, int, int, _Detector]] = []
    for d in detectors:
        for m in d.pattern.finditer(view):
            g = next((g for g in d.group if m.start(g) != -1), None)
            if g is None:
                continue
            start, end = m.span(g)
            if end > start and d.valid(m.group(g)):
                candidates.append((d.priority, start, end, d))
    chosen: list[tuple[int, int, _Detector]] = []
    for _, start, end, d in sorted(candidates, key=lambda c: (c[0], c[1])):
        if all(end <= s or start >= e for s, e, _ in chosen):
            chosen.append((start, end, d))
    spans = sorted(chosen, key=lambda c: c[0])
    if index is None:
        return spans
    return [(index[s], index[e - 1] + 1, d) for s, e, d in spans]


def find_sensitive(text: str) -> list[tuple[int, int, str]]:
    """(start, end, type) of every secret and PII match, with the masker's rules. Used by the output filter."""
    return [(start, end, d.type) for start, end, d in _find(text, _DETECTORS)]


def redact_sensitive(text: str) -> str:
    """``text`` with every secret and PII match replaced by ``[REDACTED:<type>]``. For audit copies (I8)."""
    out, pos = [], 0
    for start, end, kind in find_sensitive(text):
        out += [text[pos:start], f"[REDACTED:{kind}]"]
        pos = end
    out.append(text[pos:])
    return "".join(out)


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------


class _Masker:
    """Per-request state: one vault, one counter per token prefix, one token per distinct value."""

    def __init__(self, policy: Policy, taken: str) -> None:
        self.modes = {
            "secrets": setting(policy, "prompt_controls.secrets.mode"),
            "pii": setting(policy, "prompt_controls.pii.mode"),
        }
        pii_types = set(setting(policy, "prompt_controls.pii.types"))
        self.detectors = [
            d for d in _DETECTORS
            if self.modes[d.control] != "off" and (d.control == "secrets" or d.type in pii_types)
        ]
        self.taken = taken  # all original text: tokens the user typed are never reused
        self.vault = Vault()
        self.findings: list[Finding] = []
        self._counters: dict[str, int] = {}
        self._tokens: dict[tuple[str, str], str] = {}

    def _token(self, prefix: str, value: str) -> str:
        key = (prefix, value)
        if key not in self._tokens:
            n = self._counters.get(prefix, 0)
            while True:
                n += 1
                token = f"[{prefix}_{n}]"
                if token not in self.taken:
                    break
            self._counters[prefix] = n
            self._tokens[key] = token
            self.vault.add_mask(token, value)
        return self._tokens[key]

    def mask(self, text: str) -> str:
        out, pos = [], 0
        for start, end, d in _find(text, self.detectors):
            mode = self.modes[d.control]
            if mode == "log":
                self.findings.append(Finding(d.type, "", "log"))
                continue
            prefix = "SECRET" if d.control == "secrets" else d.type.upper()
            token = self._token(prefix, text[start:end])
            self.findings.append(Finding(d.type, token, "block" if mode == "block" else "redact"))
            out.append(text[pos:start])
            out.append(token)
            pos = end
        out.append(text[pos:])
        return "".join(out)


def _rewrite(m: dict[str, Any], fn: Callable[[str], str]) -> None:
    """Apply ``fn`` to every client-written text field of one message, in place.

    Content (string or text parts), the ``name`` field, and the function name and
    arguments of ``tool_calls`` (forged assistant turns are client data too).
    """
    content = m.get("content")
    if isinstance(content, str):
        m["content"] = fn(content)
    elif isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                part["text"] = fn(part["text"])
    if isinstance(m.get("name"), str):
        m["name"] = fn(m["name"])
    for call in m.get("tool_calls") or []:
        fn_call = call.get("function") if isinstance(call, dict) else None
        if isinstance(fn_call, dict):
            for key in ("name", "arguments"):
                if isinstance(fn_call.get(key), str):
                    fn_call[key] = fn(fn_call[key])


def client_texts(messages: list[dict[str, Any]]) -> list[str]:
    """Every client-written text field of ``messages`` (see ``_rewrite``), in order."""
    seen: list[str] = []
    for m in copy.deepcopy(messages):
        if isinstance(m, dict):
            _rewrite(m, lambda t: seen.append(t) or t)
    return seen


def mask_messages(messages: list[dict[str, Any]], policy: Policy) -> tuple[list[dict[str, Any]], Vault, list[Finding]]:
    """Mask secrets and PII in every client message, whatever its role. Spec section 4 step 3a-3b.

    Every message the client sends is untrusted (spec section 4 step 3), including
    system, developer and assistant turns. Returns new messages (the input is not
    modified), the vault holding the originals, and findings with type, token and
    action, never values (I8). ``block`` mode still masks; ``masking_decisions``
    turns it into a block.
    """
    masker = _Masker(policy, "\n".join(client_texts(messages)))
    out = copy.deepcopy(messages)
    for m in out:
        if isinstance(m, dict):
            _rewrite(m, masker.mask)
    return out, masker.vault, masker.findings


_CONTROL = {d.type: d.control for d in _DETECTORS}
_LABEL = {"secrets": "secret", "pii": "personal data"}


def masking_decisions(findings: list[Finding]) -> list[Decision]:
    """One decision per control that found something; a single allow if nothing was found."""
    decisions: list[Decision] = []
    for control in ("secrets", "pii"):
        found = [f for f in findings if _CONTROL.get(f.type) == control]
        if not found:
            continue
        types = ", ".join(sorted({f.type for f in found}))
        label = _LABEL[control]
        if any(f.action == "block" for f in found):
            decisions.append(Decision(STAGE, control, "block", f"The request contains a {label} ({types}); blocked by policy."))
        elif any(f.action == "redact" for f in found):
            decisions.append(Decision(STAGE, control, "redact", f"Masked {len(found)} {label} value(s) ({types})."))
        else:
            decisions.append(Decision(STAGE, control, "log", f"Detected {label} ({types}); logged only."))
    return decisions or [Decision(STAGE, "masker", "allow", "No secrets or personal data found.")]


def inspect_inbound(
    req: ChatRequest, p: Principal, policy: Policy, cache: IssuedCache
) -> tuple[SanitizedRequest, Vault, list[Decision]]:
    """Mask user messages and tool results, re-mask history, scan tool definitions. Spec section 4 step 3a-3d.

    History re-masking (3c) runs first, so a value issued earlier is replaced by the
    prior-value marker before the masker could turn it into a mask token. Then every
    message, whatever its role, is masked (3a-3b); tool results stay ``role: tool`` and
    are checked on surface ``tool_result`` in step 4. Tool definitions are scanned
    against the feed named by the policy (3d); an unreadable feed raises (fail closed).
    """
    from gateway.inbound.history import remask_history  # history and injection import this module
    from gateway.inbound.injection import scan_tool_definitions

    messages, _ = remask_history([m.model_dump(exclude_none=True) for m in req.messages], p, cache, policy)
    messages, vault, findings = mask_messages(messages, policy)
    tools = list(req.tools or [])
    decisions = masking_decisions(findings)
    if tools:
        decisions.append(scan_tool_definitions(tools, policy, _feed(policy)))
    return SanitizedRequest(messages=messages, tools=tools, findings=findings), vault, decisions


_FEEDS: dict[Path, FeedStore] = {}


def _feed(policy: Policy) -> SignatureFeed:
    """The feed named by ``prompt_controls.signatures.feed``, relative to the policy file; reloads by mtime."""
    path = Path(setting(policy, "prompt_controls.signatures.feed"))
    if not path.is_absolute():
        path = policy_path().parent / path
    return _FEEDS.setdefault(path, FeedStore(path)).snapshot()
