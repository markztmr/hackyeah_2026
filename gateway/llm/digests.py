"""Model digest pinning. Spec section 9 'Malicious or swapped models', section 8. Owner: Person 1.

Each ``models.allowed`` entry may pin a ``digest`` (``sha256:<64 hex>``, as Ollama
``/api/tags`` reports it, with or without the prefix). The installed digests are read
from ``/api/tags`` of every Ollama base URL in the policy (answer and judge):

- at startup and on ``POST /policy/reload`` and ``GET /health`` (``force=True``);
- lazily, the first time a policy version is used (an mtime reload);
- again after ``RETRY_S`` while Ollama could not be reached.

Per model: ``ok`` (pin matches), ``unpinned`` (no digest in the policy: external models),
``mismatch`` (different digest, or a pin that is not a sha256 value), ``missing`` (pinned
but not installed) or ``unverified`` (``/api/tags`` unreachable or unreadable). Everything
except ``ok`` and ``unpinned`` blocks the model (I6): ``block_reason`` is used by
``budget.resolve_model``, so the answer model and the judge are both covered.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from gateway.models import Policy
from gateway.policy.loader import setting

log = logging.getLogger(__name__)

Status = Literal["ok", "unpinned", "mismatch", "missing", "unverified"]
ALLOWED_STATUSES: frozenset[str] = frozenset({"ok", "unpinned"})
TAGS_TIMEOUT_S = 2.0
RETRY_S = 15.0  # an unverified check is retried after this many seconds
_HEX = re.compile(r"[0-9a-f]{64}")
_REASONS: dict[str, str] = {
    "mismatch": "The model's digest does not match the pinned digest; model blocked.",
    "missing": "The pinned model is not installed in Ollama; model blocked.",
    "unverified": "The model's digest could not be verified (Ollama /api/tags unreachable); model blocked.",
}


@dataclass(frozen=True, slots=True)
class ModelDigest:
    """Digest status of one allowed model. Digests are shown shortened (12 hex)."""

    status: Status
    pinned: str | None = None
    installed: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "pinned": self.pinned, "installed": self.installed}


def normalize_digest(value: Any) -> str | None:
    """64 lowercase hex characters, from ``sha256:<hex>`` or ``<hex>``; None if not a sha256 value."""
    if not isinstance(value, str):
        return None
    s = value.strip().lower()
    s = s.removeprefix("sha256:")
    return s if _HEX.fullmatch(s) else None


def _short(digest: str | None) -> str | None:
    return "sha256:" + digest[:12] if digest else None


def ollama_root(base_url: str) -> str:
    """``http://host:11434/v1`` -> ``http://host:11434`` (``/api/tags`` lives at the root)."""
    root = base_url.rstrip("/")
    return root[: -len("/v1")] if root.endswith("/v1") else root


def fetch_installed(base_url: str, timeout_s: float = TAGS_TIMEOUT_S) -> dict[str, str]:
    """Name -> normalized digest from ``GET <root>/api/tags``. Raises on any error or unexpected shape."""
    r = httpx.get(ollama_root(base_url) + "/api/tags", timeout=timeout_s)
    r.raise_for_status()
    models = r.json().get("models")
    if not isinstance(models, list):
        raise ValueError("Unexpected /api/tags response.")
    out: dict[str, str] = {}
    for m in models:
        if not isinstance(m, Mapping):
            raise ValueError("Unexpected /api/tags entry.")
        digest = normalize_digest(m.get("digest"))
        for key in ("name", "model"):
            name = m.get(key)
            if isinstance(name, str) and name and digest:
                out[name] = digest
    return out


def installed_digests(policy: Policy) -> dict[str, str] | None:
    """Installed digests from every Ollama base URL in the policy; None if any of them cannot be read."""
    urls = {setting(policy, f"models.{p}.base_url") for p in ("answer", "judge")
            if setting(policy, f"models.{p}.provider") == "ollama"}
    out: dict[str, str] = {}
    try:
        for url in sorted(urls):
            out.update(fetch_installed(url))
    except Exception as e:  # noqa: BLE001 - unreadable tags make pinned models unverified (I6)
        log.warning("Ollama /api/tags could not be read (%s).", type(e).__name__)
        return None
    return out


def _lookup(name: str, installed: Mapping[str, str]) -> str | None:
    """Ollama lists an untagged name as ``<name>:latest``."""
    if name in installed:
        return installed[name]
    return installed.get(name + ":latest") if ":" not in name else None


def evaluate(policy: Policy, installed: Mapping[str, str] | None) -> dict[str, ModelDigest]:
    """Status of every ``models.allowed`` entry against the installed digests (None = unreachable)."""
    out: dict[str, ModelDigest] = {}
    for entry in setting(policy, "models.allowed"):
        name, raw_pin = entry["name"], entry.get("digest")
        if raw_pin is None:
            out[name] = ModelDigest("unpinned")
            continue
        pin = normalize_digest(raw_pin)
        if pin is None:
            out[name] = ModelDigest("mismatch")  # a placeholder or malformed pin never matches
            continue
        if installed is None:
            out[name] = ModelDigest("unverified", _short(pin))
            continue
        actual = _lookup(name, installed)
        if actual is None:
            out[name] = ModelDigest("missing", _short(pin))
        else:
            out[name] = ModelDigest("ok" if actual == pin else "mismatch", _short(pin), _short(actual))
    return out


class _Store:
    """Last check per policy version: (monotonic time, statuses)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._checks: dict[str, tuple[float, dict[str, ModelDigest]]] = {}

    def clear(self) -> None:
        with self._lock:
            self._checks.clear()

    def get(self, policy: Policy, *, force: bool = False) -> dict[str, ModelDigest]:
        with self._lock:
            now = time.monotonic()
            cached = self._checks.get(policy.version_hash)
            stale = cached is None or force or (
                now - cached[0] >= RETRY_S and any(d.status == "unverified" for d in cached[1].values()))
            if stale:
                result = evaluate(policy, installed_digests(policy))
                for name, d in result.items():
                    if d.status not in ALLOWED_STATUSES:
                        log.warning("Model %s blocked: digest %s.", name, d.status)
                self._checks = {policy.version_hash: (now, result)}  # only the current version is kept
                return result
            return cached[1]  # type: ignore[index]


_STORE = _Store()


def check_digests(policy: Policy, *, force: bool = False) -> dict[str, ModelDigest]:
    """Digest status of every allowed model. ``force`` re-reads /api/tags (startup, reload, /health)."""
    return _STORE.get(policy, force=force)


def block_reason(model: str, policy: Policy) -> str | None:
    """Why this allowed model is blocked by its digest, or None if it may be used. Fails closed."""
    try:
        d = check_digests(policy).get(model)
    except Exception:  # noqa: BLE001 - a failing check denies (I6)
        return "The model digest check failed; model blocked."
    if d is None:
        return "The model digest check failed; model blocked."
    return None if d.status in ALLOWED_STATUSES else _REASONS[d.status]


def health(policy: Policy) -> dict[str, Any]:
    """``/health`` section: a fresh check, every model's status, ``ok`` when none is blocked."""
    result = check_digests(policy, force=True)
    return {
        "checked": True,
        "ok": all(d.status in ALLOWED_STATUSES for d in result.values()),
        "models": {name: d.as_dict() for name, d in result.items()},
    }
