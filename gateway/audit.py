"""Audit records, JSONL, CSV export. Spec section 4 step 10, section 13. Owner: Person 4.

Minimal version by Person 1 for the pipeline and /audit/export. Records carry
types, statuses and reasons, never values (I8): ``AuditRecord`` has no value fields.
"""
from __future__ import annotations

import csv
import dataclasses
import io
import json
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from gateway.models import AuditRecord, Policy
from gateway.policy.loader import REPO_ROOT, setting

_lock = threading.Lock()

CSV_COLUMNS = (
    "request_id", "timestamp", "verdict", "user_id", "role", "department", "ai_data_policy",
    "answer_model", "policy_version", "feed_version", "decisions", "bindings", "tool_decisions",
    "tool_iterations", "disabled_controls", "prompt_tokens", "completion_tokens", "judge_tokens",
    "cost_usd", "total_latency_ms",
)


def audit_path(policy: Policy) -> Path:
    """``ACL_AUDIT_PATH`` if set (tests), else ``audit.path``; relative paths are under the repo root."""
    path = Path(os.environ.get("ACL_AUDIT_PATH") or setting(policy, "audit.path"))
    return path if path.is_absolute() else REPO_ROOT / path


def write_audit(record: AuditRecord, policy: Policy) -> None:
    """Append exactly one audit record for the request; never values. Spec section 4 step 10, I8, I12."""
    line = json.dumps(dataclasses.asdict(record), ensure_ascii=False, default=str)
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
