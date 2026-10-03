"""Feed loading and matching per surface. Spec section 4 step 4, section 9. Owner: Person 2.

Feed loading (``parse_feed``, ``FeedStore``) added by Person 1 for the pipeline and /health.
"""
from __future__ import annotations

import hashlib
import json
import re

from gateway.models import Decision, Signature, SignatureFeed
from gateway.policy.loader import ReloadingFile

SURFACES = frozenset({"input", "tool_result", "tool_definition", "model_output", "tool_args", "url"})
SEVERITIES = frozenset({"high", "medium", "low"})
TYPES = frozenset({"regex", "substring"})
_FIELDS = ("id", "category", "severity", "applies_to", "type", "pattern")


class FeedError(ValueError):
    """signatures.json is invalid. Messages name entries and fields, never patterns."""


def parse_feed(raw: bytes) -> SignatureFeed:
    """Validate signatures.json (spec section 9). Version is the file's ``version``, else its sha256."""
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        raise FeedError("Signature feed is not valid JSON.") from None
    if not isinstance(data, dict):
        raise FeedError("Signature feed must be a JSON object.")
    entries = data.get("signatures", [])
    if not isinstance(entries, list):
        raise FeedError("signatures: expected a list.")
    signatures: list[Signature] = []
    seen: set[str] = set()
    for i, e in enumerate(entries):
        where = f"signatures[{i}]"
        if not isinstance(e, dict) or any(f not in e for f in _FIELDS):
            raise FeedError(f"{where}: needs {', '.join(_FIELDS)}.")
        if not all(isinstance(e[f], str) and e[f] for f in _FIELDS if f != "applies_to"):
            raise FeedError(f"{where}: fields must be non-empty strings.")
        applies = e["applies_to"]
        if not isinstance(applies, list) or not applies or not set(applies) <= SURFACES:
            raise FeedError(f"{where}.applies_to: expected a list of {', '.join(sorted(SURFACES))}.")
        if e["severity"] not in SEVERITIES or e["type"] not in TYPES:
            raise FeedError(f"{where}: unknown severity or type.")
        if e["type"] == "regex":
            try:
                re.compile(e["pattern"])
            except re.error:
                raise FeedError(f"{where}.pattern: not a valid regular expression.") from None
        if e["id"] in seen:
            raise FeedError(f"{where}.id: duplicate id.")
        seen.add(e["id"])
        signatures.append(Signature(e["id"], e["category"], e["severity"], tuple(applies), e["type"], e["pattern"]))
    version = data.get("version")
    if not isinstance(version, str) or not version:
        version = "sha256:" + hashlib.sha256(raw).hexdigest()[:16]
    return SignatureFeed(version=version, signatures=tuple(signatures))


class FeedStore(ReloadingFile[SignatureFeed]):
    """signatures.json, reloaded by mtime like the policy (spec section 6 'Live reload contract')."""

    _label = "Signature feed"

    def _parse(self, raw: bytes) -> SignatureFeed:
        return parse_feed(raw)

    def _version(self, value: SignatureFeed) -> str:
        return value.version

    def _extra_status(self, value: SignatureFeed) -> dict[str, int]:
        return {"signatures": len(value.signatures)}


def match_signatures(text: str, surface: str, feed: SignatureFeed) -> Decision:
    """Match text against feed entries that apply to this surface. Spec section 4 step 4, section 9."""
    raise NotImplementedError
