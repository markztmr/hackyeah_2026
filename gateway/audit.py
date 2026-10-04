"""Audit records, JSONL, CSV export. Spec section 4 step 10, section 13. Owner: Person 4.

Records carry types, statuses and reasons, never values (I8): ``AuditRecord`` has no
value fields, and the pipeline copies model-written SQL and purposes only after removing
literals and secrets. Prompt text is the newest user message after masking, or nothing,
per ``audit.log_prompt_text`` (never raw).

``write_audit`` is the last line of defence: before appending, ``find_request_values``
looks for any vault original or binding value of the current request in the record's
text. If one is found, the record is still written (one per request, I17) but with its
free text withheld: reasons, SQL, purposes, prompt text and tool arguments are dropped,
and one ``audit.guard`` decision says so.
"""
from __future__ import annotations

import csv
import dataclasses
import io
import json
import os
import html
import logging
import math
import re
import threading
from collections.abc import Iterator, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from gateway.budget import limits
from gateway.models import AuditRecord, Binding, Decision, Policy, Principal, SignatureFeed, Vault
from gateway.policy.loader import REPO_ROOT, setting

log = logging.getLogger(__name__)
_lock = threading.Lock()

# Fields the gateway sets from authentication, configuration and its own clock: not request values.
_UNGUARDED = frozenset({
    "request_id", "timestamp", "policy_version", "feed_version", "verdict", "user_id", "role",
    "department", "ai_data_policy", "answer_model", "judge_model", "disabled_controls", "step_latency_ms",
})
MIN_GUARDED_LENGTH = 3  # shorter values ("1", "25", "ok") match everywhere and reveal little
WITHHELD = "Record details withheld: they contained a value from this request."

CSV_COLUMNS = (
    "request_id", "timestamp", "verdict", "user_id", "role", "department", "ai_data_policy",
    "answer_model", "policy_version", "feed_version", "decisions", "bindings", "tool_decisions",
    "tool_iterations", "disabled_controls", "prompt_tokens", "completion_tokens", "judge_tokens",
    "cost_usd", "total_latency_ms", "prompt_text",
)


def audit_path(policy: Policy) -> Path:
    """``ACL_AUDIT_PATH`` if set (tests), else ``audit.path``; relative paths are under the repo root."""
    path = Path(os.environ.get("ACL_AUDIT_PATH") or setting(policy, "audit.path"))
    return path if path.is_absolute() else REPO_ROOT / path


def _number_forms(n: int | float) -> set[str]:
    """How a number may be written: 6200, 6200.0, 6,200, 6 200, 6.200 (and 7,499.5 for 7499.5)."""
    forms = {str(n)}
    if isinstance(n, float) and n.is_integer():
        n = int(n)
        forms.add(str(n))
    if isinstance(n, int):
        forms |= {str(n) + ".0", format(n, ",")}
        forms |= {format(n, ",").replace(",", sep) for sep in (" ", ".", "\u00a0", "\u202f")}
    elif math.isfinite(n) and "e" not in repr(n):
        forms.add(format(n, ","))
    return forms


def _value_forms(b: Binding) -> set[str]:
    """Text a binding's value may appear as: the whole value, number spellings, list and row cells."""
    v = b.value
    if v is None:
        return set()
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return _number_forms(v)
    text = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
    forms = {text}
    lines = text.splitlines()
    if b.expect == "list" and len(lines) > 2:  # markdown table: header, separator, rows
        for line in lines[2:]:  # cells were escaped for markdown by the executor
            forms |= {html.unescape(re.sub(r"\\(.)", r"\1", c)) for c in re.split(r"(?<!\\)\|", line)}
    elif b.expect == "row":  # "col: value, col: value"
        forms |= {part.partition(": ")[2] for part in text.split(", ")}
    out: set[str] = set()
    for f in forms:
        f = f.strip()
        out.add(f)
        if re.fullmatch(r"-?\d+(\.\d+)?", f):
            out |= _number_forms(float(f) if "." in f else int(f))
    return out


def _texts(value: Any, path: str) -> Iterator[tuple[str, str]]:
    """(path, text) for every string in a JSON-like value, keys included."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for k, v in value.items():
            yield path, str(k)
            yield from _texts(v, path + "." + str(k))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _texts(v, path + "[" + str(i) + "]")


def find_request_values(
    record: AuditRecord, *, vault: Vault | None = None, bindings: Mapping[str, Binding] | None = None
) -> list[str]:
    """Paths of record fields that contain a vault original or a binding value of this request (I8).

    Vault originals match anywhere, case-insensitively. Binding values of at least
    ``MIN_GUARDED_LENGTH`` characters match as whole tokens (not inside a longer word or
    number), case-insensitively, in any number spelling. Paths only, never the values.
    """
    patterns = [
        re.compile(r"(?<![0-9A-Za-z])" + re.escape(f) + r"(?![0-9A-Za-z])", re.IGNORECASE)
        for b in (bindings or {}).values() for f in _value_forms(b) if len(f) >= MIN_GUARDED_LENGTH
    ]
    found: list[str] = []
    data = dataclasses.asdict(record)
    for key, value in data.items():
        if key in _UNGUARDED:
            continue
        for path, text in _texts(value, key):
            if path not in found and ((vault is not None and vault.appears_in(text))
                                      or any(p.search(text) for p in patterns)):
                found.append(path)
    return found


def _withheld(record: AuditRecord) -> AuditRecord:
    """The record with every free-text field emptied; counts, statuses and identity stay."""
    return dataclasses.replace(
        record,
        decisions=[Decision("audit", "audit.guard", "log", WITHHELD)],
        bindings=[dataclasses.replace(b, sql="", purpose="", reason="", tables=[], columns=[])
                  for b in record.bindings],
        tool_decisions=[dataclasses.replace(t, tool="", reason="") for t in record.tool_decisions],
        prompt_text=None,
    )


def _rounded(data: dict[str, Any]) -> dict[str, Any]:
    """Latencies to the microsecond: finer digits are noise."""
    data["total_latency_ms"] = round(data["total_latency_ms"], 3)
    data["step_latency_ms"] = {k: round(v, 3) for k, v in data["step_latency_ms"].items()}
    for item in (*data["decisions"], *data["bindings"]):
        item["latency_ms"] = round(item["latency_ms"], 3)
    return data


def write_audit(
    record: AuditRecord, policy: Policy, *, vault: Vault | None = None, bindings: Mapping[str, Binding] | None = None
) -> None:
    """Append exactly one audit record for the request; never values. Spec section 4 step 10, I8, I17.

    ``vault`` and ``bindings`` are the current request's; a record containing any of their
    values is written with its details withheld.
    """
    if setting(policy, "audit.log_prompt_text") == "none":
        record = dataclasses.replace(record, prompt_text=None)
    hits = find_request_values(record, vault=vault, bindings=bindings)
    if hits:
        log.warning("Audit record %s held request values in %s; details withheld.", record.request_id, hits)
        record = _withheld(record)
        if find_request_values(record, vault=vault, bindings=bindings):
            raise ValueError("Audit record still holds a request value after withholding.")
    line = json.dumps(_rounded(dataclasses.asdict(record)), ensure_ascii=False, default=str)
    path = audit_path(policy)
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def read_audit(policy: Policy, since: datetime | None = None, until: datetime | None = None) -> list[dict[str, Any]]:
    """Audit records in file order, optionally limited to ``since <= timestamp < until``. Bad lines are skipped."""
    path = audit_path(policy)
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
                ts = datetime.fromisoformat(rec["timestamp"])
            except (ValueError, KeyError, TypeError):
                continue
            if (since and ts < since) or (until and ts >= until):
                continue
            out.append(rec)
    return out


def _cell(value: Any) -> str:
    """One CSV cell. Leading = + - @ are escaped so spreadsheets never evaluate model-written text."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _summaries(rec: dict[str, Any]) -> dict[str, Any]:
    return {
        "decisions": "; ".join(f"{d['stage']}/{d['control']}: {d['verdict']}" for d in rec.get("decisions", [])),
        "bindings": "; ".join(f"{b['name']}: {b['status']}" for b in rec.get("bindings", [])),
        "tool_decisions": "; ".join(f"{t['tool']}: {t['verdict']}" for t in rec.get("tool_decisions", [])),
        "disabled_controls": "; ".join(rec.get("disabled_controls", [])),
    }


def export_csv(records: list[dict[str, Any]]) -> str:
    """CSV for security teams: one row per request, nested parts summarized."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    for rec in records:
        row = {**rec, **_summaries(rec)}
        writer.writerow([_cell(row.get(c, "")) if row.get(c) is not None else "" for c in CSV_COLUMNS])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# GET /metrics: dashboard sections computed from the audit log
# ---------------------------------------------------------------------------

LAST_REQUESTS = 50
_VERDICTS = ("allow", "redact", "block", "log")
BINDING_STATUSES = ("resolved", "denied", "rejected", "empty", "error")
TOOL_VERDICTS = ("allow", "deny")
WINDOW_MINUTES = 60
NO_TABLE = "(none)"  # a binding rejected before its tables were known
_ID_SPLIT = re.compile(r"[\s,;()]+")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _deciding(rec: dict[str, Any]) -> tuple[str | None, str | None]:
    """(control, reason) behind a record's verdict: the first decision with that verdict,
    else the first denied tool call (every call removed), else nothing."""
    verdict = rec.get("verdict")
    if verdict == "allow":
        return None, None
    for d in rec.get("decisions") or []:
        if d.get("verdict") == verdict:
            return d.get("control"), d.get("reason")
    for t in rec.get("tool_decisions") or []:
        if t.get("verdict") == "deny":
            return "tool_authz." + str(t.get("rule")), t.get("reason")
    return None, None


def _is_day(rec: dict[str, Any], day: str) -> bool:
    try:
        return datetime.fromisoformat(rec["timestamp"]).astimezone(timezone.utc).date().isoformat() == day
    except (KeyError, TypeError, ValueError):
        return False


def _requests_by_verdict(today: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(_VERDICTS, 0)
    for rec in today:
        if rec.get("verdict") in counts:
            counts[rec["verdict"]] += 1
    return counts


def _blocks_by_control(today: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rec in today:
        if rec.get("verdict") == "block":
            control = _deciding(rec)[0] or "unknown"
            counts[control] = counts.get(control, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _tokens_and_cost_by_user(today: list[dict[str, Any]], policy: Policy, day: str) -> dict[str, Any]:
    users: dict[str, dict[str, Any]] = {}
    for rec in today:
        user = rec.get("user_id")
        if not user:
            continue
        u = users.setdefault(user, {"role": rec.get("role"), "tokens": 0, "cost_usd": 0.0})
        u["tokens"] += sum(int(rec.get(k) or 0) for k in ("prompt_tokens", "completion_tokens", "judge_tokens"))
        u["cost_usd"] = round(u["cost_usd"] + float(rec.get("cost_usd") or 0.0), 6)
    for user, u in users.items():
        u["limits"] = limits(Principal(user, str(u["role"]), "", "deny"), policy)
    return {"day": day, "users": dict(sorted(users.items()))}


def _last_requests(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for rec in reversed(records[-LAST_REQUESTS:]):
        control, reason = _deciding(rec)
        rows.append({"time": rec.get("timestamp"), "request_id": rec.get("request_id"), "user": rec.get("user_id"),
                     "role": rec.get("role"), "verdict": rec.get("verdict"), "control": control, "reason": reason})
    return rows


def _time(rec: dict[str, Any]) -> datetime | None:
    try:
        return datetime.fromisoformat(rec["timestamp"]).astimezone(timezone.utc)
    except (KeyError, TypeError, ValueError):
        return None


def _blocks_by_signature_category(today: list[dict[str, Any]], feed: SignatureFeed | None) -> dict[str, int]:
    """Blocked requests per category of the signatures named in their blocking ``signatures``
    decisions (once per request and category). IDs are matched as whole tokens against the
    current feed; an ID no longer in it counts as ``unknown``."""
    categories = {s.id: s.category for s in (feed.signatures if feed is not None else ())}
    counts: dict[str, int] = {}
    for rec in today:
        if rec.get("verdict") != "block":
            continue
        found: set[str] = set()
        for d in rec.get("decisions") or []:
            if d.get("verdict") != "block" or d.get("control") != "signatures":
                continue
            ids = [t for t in _ID_SPLIT.split(str(d.get("reason") or "")) if t in categories]
            found |= {categories[i] for i in ids} or {"unknown"}
        for category in found:
            counts[category] = counts.get(category, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _blocks_over_time(records: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    """Requests and blocks per minute for the last hour, oldest first, empty minutes included."""
    end = now.replace(second=0, microsecond=0)
    start = end - timedelta(minutes=WINDOW_MINUTES - 1)
    buckets: list[dict[str, Any]] = [
        {"minute": (start + timedelta(minutes=i)).isoformat(), "requests": 0, "blocks": 0}
        for i in range(WINDOW_MINUTES)]
    for rec in records:
        ts = _time(rec)
        if ts is None:
            continue
        i = int((ts.replace(second=0, microsecond=0) - start).total_seconds() // 60)
        if 0 <= i < WINDOW_MINUTES:
            buckets[i]["requests"] += 1
            buckets[i]["blocks"] += int(rec.get("verdict") == "block")
    return buckets


def _blocks_by_user(today: list[dict[str, Any]]) -> dict[str, int]:
    """Blocked requests per authenticated user, most first (401s have no user and are not listed)."""
    counts: dict[str, int] = {}
    for rec in today:
        if rec.get("verdict") == "block" and rec.get("user_id"):
            counts[rec["user_id"]] = counts.get(rec["user_id"], 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _binding_outcomes(today: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, int]]]:
    """role -> table -> outcome counts. A binding that read several tables counts once for each."""
    out: dict[str, dict[str, dict[str, int]]] = {}
    for rec in today:
        role = rec.get("role") or "(unauthenticated)"
        for b in rec.get("bindings") or []:
            status = b.get("status")
            if status not in BINDING_STATUSES:
                continue
            for table in sorted({str(t).lower() for t in b.get("tables") or []}) or [NO_TABLE]:
                cell = out.setdefault(role, {}).setdefault(table, dict.fromkeys(BINDING_STATUSES, 0))
                cell[status] += 1
    return {r: dict(sorted(t.items())) for r, t in sorted(out.items())}


def _tool_decisions_by_tool(today: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """tool -> allow / deny counts of client tool calls."""
    out: dict[str, dict[str, int]] = {}
    for rec in today:
        for t in rec.get("tool_decisions") or []:
            if t.get("verdict") in TOOL_VERDICTS:
                cell = out.setdefault(str(t.get("tool")), dict.fromkeys(TOOL_VERDICTS, 0))
                cell[t["verdict"]] += 1
    return dict(sorted(out.items()))


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return float(value)


def _percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile of a non-empty list."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def _latency_by_step(today: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    """Median and p95 (nearest rank) in ms per pipeline step, in pipeline order, then ``total``."""
    samples: dict[str, list[float]] = {}
    totals: list[float] = []
    for rec in today:
        for step, ms in (rec.get("step_latency_ms") or {}).items():
            if _number(ms) is not None:
                samples.setdefault(str(step), []).append(float(ms))
        total = _number(rec.get("total_latency_ms"))
        if total is not None and rec.get("step_latency_ms"):
            totals.append(total)
    if totals:
        samples.pop("total", None)
        samples["total"] = totals
    return {step: {"median_ms": round(_percentile(v, 0.5), 3), "p95_ms": round(_percentile(v, 0.95), 3),
                   "count": len(v)} for step, v in samples.items()}


def audit_metrics(records: list[dict[str, Any]], policy: Policy, *, now: datetime | None = None,
                  feed: SignatureFeed | None = None) -> dict[str, Any]:
    """Dashboard sections for GET /metrics, from audit records in file order. Spec section 12.

    A dict of independent sections; new sections are added as new keys. Counts, usage and
    latency cover today (UTC), the budget day; ``last_requests`` is the newest 50 whatever
    the day; ``blocks_over_time`` is the last 60 minutes. ``feed`` maps signature IDs to
    categories. Everything comes from audit records, which hold no values (I8).
    """
    now = (now or _utcnow()).astimezone(timezone.utc)
    day = now.date().isoformat()
    today = [r for r in records if _is_day(r, day)]
    return {
        "requests_by_verdict": _requests_by_verdict(today),
        "blocks_by_control": _blocks_by_control(today),
        "tokens_and_cost_by_user": _tokens_and_cost_by_user(today, policy, day),
        "last_requests": _last_requests(records),
        "blocks_by_signature_category": _blocks_by_signature_category(today, feed),
        "blocks_over_time": _blocks_over_time(records, now),
        "blocks_by_user": _blocks_by_user(today),
        "binding_outcomes_by_role_and_table": _binding_outcomes(today),
        "tool_decisions_by_tool": _tool_decisions_by_tool(today),
        "latency_by_step": _latency_by_step(today),
    }
