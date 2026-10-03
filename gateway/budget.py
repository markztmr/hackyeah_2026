"""Check and record usage (state.db). Spec section 4 steps 2 and 10, section 6 (budgets). Owner: Person 4.

Model allowlist part by Person 1. Digest pinning (Tier 2) is not implemented yet.

Counters live in their own SQLite file, ``ACL_STATE_PATH`` (tests) or ``budgets.store``
(relative to the repository root). This module is the only one that opens it, and it
refuses to open the data database (I1: ``demo.db`` stays the executor's alone).

- Limits per user: ``budgets.<role>`` overrides key by key, then ``budgets.default``
  (whose missing keys come from the profile).
- ``tokens_per_day`` and ``cost_per_day_usd``: checked before every model call (answer,
  each loop iteration, judge) against the UTC day's usage plus the call's estimate
  (prompt characters / 4 + ``max_tokens``, computed by the caller). I18.
- ``requests_per_minute``: a sliding 60-second window of admitted requests, checked and
  counted once per gateway request in step 2 (``admit_request``). Blocked requests are
  not counted.
- ``record_usage`` adds actual tokens and their cost (``pricing_per_1k_tokens``; an
  unpriced model costs 0) right after each model call. Judge usage counts only if
  ``count_judge_tokens``.

Any failure in a check blocks (I6). Reasons never contain counters or limits.
"""
from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Iterator, Mapping
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gateway.binding.executor import db_path
from gateway.models import Decision, Policy, Principal
from gateway.policy.loader import setting

STAGE = "model_and_budget"
REPO_ROOT = Path(__file__).resolve().parent.parent
WINDOW_S = 60.0
_LIMITS = ("tokens_per_day", "requests_per_minute", "cost_per_day_usd")
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS usage (user_id TEXT NOT NULL, day TEXT NOT NULL,"
    " tokens INTEGER NOT NULL, cost_usd REAL NOT NULL, PRIMARY KEY (user_id, day))",
    "CREATE TABLE IF NOT EXISTS requests (user_id TEXT NOT NULL, ts REAL NOT NULL)",
    "CREATE INDEX IF NOT EXISTS requests_by_user ON requests (user_id, ts)",
)


def _now() -> float:
    return time.time()


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).date().isoformat()


def state_path(policy: Policy) -> Path:
    """``ACL_STATE_PATH`` if set (tests), else ``budgets.store``; relative paths are under the repo root."""
    path = Path(os.environ.get("ACL_STATE_PATH") or setting(policy, "budgets.store"))
    return path if path.is_absolute() else REPO_ROOT / path


@contextmanager
def _store(policy: Policy) -> Iterator[sqlite3.Connection]:
    path = state_path(policy)
    if path.resolve() == db_path().resolve():
        raise ValueError("The budget store must not be the data database.")
    with closing(sqlite3.connect(path, timeout=5.0, isolation_level=None)) as conn:
        for statement in _SCHEMA:
            conn.execute(statement)
        yield conn


def limits(p: Principal, policy: Policy) -> dict[str, float]:
    """Effective limits for this user: role override key by key, then ``budgets.default``."""
    budgets = setting(policy, "budgets")
    out = {k: budgets["default"][k] for k in _LIMITS}
    override = budgets.get(p.role)
    if isinstance(override, Mapping):
        out.update({k: override[k] for k in _LIMITS if k in override})
    return out


def _usage(conn: sqlite3.Connection, user_id: str, day: str) -> tuple[int, float]:
    row = conn.execute("SELECT tokens, cost_usd FROM usage WHERE user_id = ? AND day = ?", (user_id, day)).fetchone()
    return (int(row[0]), float(row[1])) if row else (0, 0.0)


def _count(value: Any) -> int:
    """A non-negative int token count; anything else is refused."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Token count must be a non-negative integer.")
    return value


def resolve_model(model: str, policy: Policy) -> tuple[str | None, Decision]:
    """The model to call for this request, or None if blocked. Spec section 4 step 2.

    Exact name match against ``models.allowed``. Unlisted: block, or substitute
    ``models.answer`` per ``models.on_unlisted`` (only if that model is itself allowed).
    Reasons never repeat the requested name: it is client input.
    """
    start = time.perf_counter()

    def decision(verdict: str, reason: str) -> Decision:
        return Decision(STAGE, "models.allowed", verdict, reason, (time.perf_counter() - start) * 1000)  # type: ignore[arg-type]

    try:
        allowed = {m["name"] for m in setting(policy, "models.allowed")}
        if model in allowed:
            return model, decision("allow", "Requested model is allowed.")
        answer = setting(policy, "models.answer.name")
        if setting(policy, "models.on_unlisted") == "substitute" and answer in allowed:
            return answer, decision("log", f"Requested model is not allowed; using {answer} instead.")
        return None, decision("block", "Requested model is not allowed by policy.")
    except Exception:  # noqa: BLE001 - a failing check denies (I6)
        return None, decision("block", "Model allowlist check failed.")


def check_model_and_budget(p: Principal, model: str, estimate: int, policy: Policy) -> Decision:
    """Model allowlist and budget pre-check before any model call. Spec section 4 step 2, I11, I18.

    ``estimate`` is the call's prompt characters / 4 plus its ``max_tokens``.
    """
    resolved, decision = resolve_model(model, policy)
    if resolved is None:
        return decision
    start = time.perf_counter()

    def result(verdict: str, control: str, reason: str) -> Decision:
        return Decision(STAGE, control, verdict, reason, (time.perf_counter() - start) * 1000)  # type: ignore[arg-type]

    try:
        estimate = _count(estimate)
        limit = limits(p, policy)
        with _store(policy) as conn:
            tokens, cost = _usage(conn, p.user_id, _day(_now()))
        if tokens + estimate > limit["tokens_per_day"]:
            return result("block", "budgets.tokens_per_day", "Daily token budget is exhausted.")
        if cost + cost_usd(resolved, estimate, policy) > limit["cost_per_day_usd"] + 1e-9:
            return result("block", "budgets.cost_per_day_usd", "Daily cost budget is exhausted.")
        return result("allow", "budgets", "Within budget.")
    except Exception:  # noqa: BLE001 - a failing check denies (I6)
        return result("block", "budgets", "Budget check failed.")


def admit_request(p: Principal, policy: Policy) -> Decision:
    """Count this request against ``requests_per_minute``, or block it. Once per request, step 2.

    Check and insert run in one write transaction, so concurrent requests cannot both
    take the last slot. Blocked requests are not counted.
    """
    start = time.perf_counter()

    def result(verdict: str, reason: str) -> Decision:
        return Decision(STAGE, "budgets.requests_per_minute", verdict, reason,  # type: ignore[arg-type]
                        (time.perf_counter() - start) * 1000)

    try:
        limit = limits(p, policy)["requests_per_minute"]
        now = _now()
        with _store(policy) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("DELETE FROM requests WHERE ts <= ?", (now - WINDOW_S,))
                (count,) = conn.execute(
                    "SELECT COUNT(*) FROM requests WHERE user_id = ? AND ts > ?", (p.user_id, now - WINDOW_S)
                ).fetchone()
                admitted = count < limit
                if admitted:
                    conn.execute("INSERT INTO requests (user_id, ts) VALUES (?, ?)", (p.user_id, now))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        if not admitted:
            return result("block", "Too many requests in the last minute.")
        return result("allow", "Within the request rate.")
    except Exception:  # noqa: BLE001 - a failing check denies (I6)
        return result("block", "Request rate check failed.")


def cost_usd(model: str, tokens: int, policy: Policy) -> float:
    """Notional cost from ``pricing_per_1k_tokens``; an unpriced model costs 0."""
    price = setting(policy, "pricing_per_1k_tokens").get(model, 0.0)
    return round(float(price) * tokens / 1000, 6)


def record_usage(p: Principal, tokens: int, model: str, policy: Policy, *, judge: bool = False) -> None:
    """Add actual token usage and cost to today's counters. Spec section 4 step 10.

    Called right after every model call, so the next check sees it. ``judge=True``
    usage is counted only if ``budgets.count_judge_tokens``. Raises if it cannot record.
    """
    tokens = _count(tokens)
    if tokens == 0 or (judge and not setting(policy, "budgets.count_judge_tokens")):
        return
    cost = cost_usd(model, tokens, policy)
    with _store(policy) as conn:
        conn.execute(
            "INSERT INTO usage (user_id, day, tokens, cost_usd) VALUES (?, ?, ?, ?)"
            " ON CONFLICT (user_id, day) DO UPDATE SET tokens = tokens + excluded.tokens,"
            " cost_usd = cost_usd + excluded.cost_usd",
            (p.user_id, _day(_now()), tokens, cost),
        )
