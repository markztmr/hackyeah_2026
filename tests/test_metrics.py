"""GET /metrics, computed from the audit log; the dashboard's only data besides /policy/effective.

Spec section 12 'Dashboard panels', section 13. Owner: Person 4.
"""
from __future__ import annotations

import dataclasses
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway.audit import audit_metrics, write_audit
from gateway.llm.client import StubModel, text, tool_call
from gateway.models import AuditRecord, Decision, ToolDecision
from gateway.policy.loader import load_policy
from tests.conftest import INJECTION_PHRASE
from tests.test_audit import API_KEY, SALARY_SQL, fixed_ids, masked_inbound, real_chain  # noqa: F401 - fixtures

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY = load_policy(REPO_ROOT / "policy.yaml")
ANNA = {"Authorization": "Bearer demo-anna"}
SECTIONS = {"requests_by_verdict", "blocks_by_control", "tokens_and_cost_by_user", "last_requests"}  # T1
NEW_SECTIONS = {"blocks_by_signature_category", "blocks_over_time", "blocks_by_user",
                "binding_outcomes_by_role_and_table", "tool_decisions_by_tool", "latency_by_step"}
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def _ask(client: TestClient, content: str, headers: dict[str, str] | None = None, **body: Any):
    payload = {"model": "qwen2.5:3b", "messages": [{"role": "user", "content": content}], **body}
    return client.post("/v1/chat/completions", json=payload, headers=ANNA if headers is None else headers)


def _record(i: int, verdict: str = "allow", **fields: Any) -> AuditRecord:
    return AuditRecord(request_id=f"r{i}", timestamp=f"2026-10-03T11:{i // 60:02d}:{i % 60:02d}+00:00",
                       policy_version="p", feed_version="f", verdict=verdict, **fields)  # type: ignore[arg-type]


def _metrics(*records: AuditRecord) -> dict[str, Any]:
    for r in records:
        write_audit(r, POLICY)
    from gateway.audit import read_audit
    return audit_metrics(read_audit(POLICY), POLICY, now=NOW)


@pytest.fixture
def today(monkeypatch: pytest.MonkeyPatch) -> None:
    """The metrics clock agrees with fixed_ids' timestamps."""
    from gateway import audit
    monkeypatch.setattr(audit, "_utcnow", lambda: NOW)


# ---------------------------------------------------------------------------
# Through the gateway, with the stub
# ---------------------------------------------------------------------------


def test_metrics_after_one_allowed_and_one_blocked_request(
    client: TestClient, stub: StubModel, fake_steps, masked_inbound, real_chain, fixed_ids, today, audit_records,
) -> None:
    stub.add(tool_call("query_data", {"sql": SALARY_SQL, "purpose": "own salary", "expect": "scalar"}),
             text("Your salary is {x1} PLN."))
    allowed = _ask(client, f"My key is {API_KEY}. What is my salary?")
    assert allowed.json()["choices"][0]["message"]["content"] == "Your salary is 6200 PLN."
    blocked = _ask(client, INJECTION_PHRASE)
    assert blocked.headers["x-acl-verdict"] == "block"

    r = client.get("/metrics")
    assert r.status_code == 200
    m = r.json()
    assert set(m) == SECTIONS | NEW_SECTIONS
    assert m["requests_by_verdict"] == {"allow": 1, "redact": 0, "block": 1, "log": 0}
    assert m["blocks_by_control"] == {"injection": 1}

    newest, oldest = m["last_requests"]
    assert (oldest["user"], oldest["verdict"], oldest["control"], oldest["reason"]) == ("anna", "allow", None, None)
    assert (newest["user"], newest["verdict"], newest["control"]) == ("anna", "block", "injection")
    assert newest["reason"].endswith(".") and newest["reason"][0].isupper()
    assert set(newest) == {"time", "request_id", "user", "role", "verdict", "control", "reason"}

    anna = m["tokens_and_cost_by_user"]["users"]["anna"]
    judged = sum(rec["judge_tokens"] for rec in audit_records())  # judge usage counts too (count_judge_tokens)
    assert judged > 0
    assert anna["tokens"] == allowed.json()["usage"]["total_tokens"] + blocked.json()["usage"]["total_tokens"] + judged
    assert anna["limits"] == {"tokens_per_day": 20_000, "requests_per_minute": 10, "cost_per_day_usd": 0.5}

    for raw in ("6200", "6,200", API_KEY):
        assert raw not in r.text


def test_metrics_counts_a_401_without_a_user(client: TestClient, stub: StubModel, fake_steps) -> None:
    _ask(client, "Hi", headers={"Authorization": "Bearer nope"})
    m = client.get("/metrics").json()
    assert m["requests_by_verdict"]["block"] == 1
    assert m["blocks_by_control"] == {"core.authentication": 1}
    (row,) = m["last_requests"]
    assert row["user"] is None and row["reason"] == "Invalid or missing API key."
    assert m["tokens_and_cost_by_user"]["users"] == {}


def test_metrics_with_an_empty_log(client: TestClient) -> None:
    m = client.get("/metrics").json()
    assert set(m) == SECTIONS | NEW_SECTIONS
    assert m["requests_by_verdict"] == {"allow": 0, "redact": 0, "block": 0, "log": 0}
    assert m["blocks_by_control"] == {} and m["last_requests"] == []


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def test_last_requests_are_the_newest_fifty_newest_first(audit_log: Path) -> None:
    m = _metrics(*(_record(i) for i in range(60)))
    rows = m["last_requests"]
    assert len(rows) == 50
    assert rows[0]["request_id"] == "r59" and rows[-1]["request_id"] == "r10"


def test_blocking_control_is_the_first_blocking_decision(audit_log: Path) -> None:
    m = _metrics(_record(1, "block", decisions=[
        Decision("model_and_budget", "models.allowed", "allow", "Requested model is allowed."),
        Decision("model_and_budget", "budgets.tokens_per_day", "block", "Daily token budget is exhausted."),
        Decision("output_filter", "later", "block", "Not the first."),
    ]))
    assert m["blocks_by_control"] == {"budgets.tokens_per_day": 1}
    assert m["last_requests"][0]["reason"] == "Daily token budget is exhausted."


def test_block_by_removed_tool_calls_names_the_tool_rule(audit_log: Path) -> None:
    m = _metrics(_record(1, "block", tool_decisions=[
        ToolDecision("send_email", "deny", "egress", "send_email may not carry query results.")]))
    assert m["blocks_by_control"] == {"tool_authz.egress": 1}
    assert m["last_requests"][0]["reason"] == "send_email may not carry query results."


def test_redacted_request_reports_its_redacting_control(audit_log: Path) -> None:
    m = _metrics(_record(1, "redact", decisions=[
        Decision("output_filter", "output_controls.pii", "redact", "PII in model-written text was redacted.")]))
    assert m["requests_by_verdict"]["redact"] == 1
    assert m["blocks_by_control"] == {}
    assert m["last_requests"][0]["control"] == "output_controls.pii"


def test_aggregates_cover_today_utc_only(audit_log: Path) -> None:
    yesterday = dataclasses.replace(_record(1, "block", user_id="anna", role="intern", prompt_tokens=500,
                                            decisions=[Decision("s", "injection", "block", "Old.")]),
                                    timestamp="2026-10-02T23:59:59+00:00")
    today = _record(2, user_id="anna", role="intern", prompt_tokens=100, completion_tokens=20, cost_usd=0.001)
    m = _metrics(yesterday, today)
    assert m["requests_by_verdict"] == {"allow": 1, "redact": 0, "block": 0, "log": 0}
    assert m["blocks_by_control"] == {}
    assert m["tokens_and_cost_by_user"]["day"] == "2026-10-03"
    assert m["tokens_and_cost_by_user"]["users"]["anna"]["tokens"] == 120
    assert m["tokens_and_cost_by_user"]["users"]["anna"]["cost_usd"] == pytest.approx(0.001)
    assert len(m["last_requests"]) == 2  # the feed is the newest requests, whatever the day


def test_budget_limits_use_the_role_override(audit_log: Path) -> None:
    m = _metrics(_record(1, user_id="piotr", role="hr_manager", prompt_tokens=10))
    assert m["tokens_and_cost_by_user"]["users"]["piotr"]["limits"]["tokens_per_day"] == 200_000


def test_unknown_role_in_an_old_record_has_no_limits(audit_log: Path) -> None:
    m = _metrics(_record(1, user_id="ghost", role="removed_role", prompt_tokens=10))
    assert m["tokens_and_cost_by_user"]["users"]["ghost"]["limits"] == {
        "tokens_per_day": 20_000, "requests_per_minute": 10, "cost_per_day_usd": 0.5}


# ---------------------------------------------------------------------------
# Section 12 panels: threats, data access, performance (new keys)
# ---------------------------------------------------------------------------

MAREK = {"Authorization": "Bearer demo-marek"}
SEND_EMAIL = [{"type": "function", "function": {"name": "send_email", "parameters": {"type": "object"}}}]
PICKLE = "data = pickle.loads(base64.b64decode(blob))"
DEPARTMENT_SQL = "SELECT name FROM employees WHERE department = :current_department"
CEO_SQL = "SELECT salary FROM salaries WHERE employee_id = 'katarzyna'"


def _query(sql: str, expect: str = "scalar") -> Any:
    return tool_call("query_data", {"sql": sql, "purpose": "test", "expect": expect})


def _nearest_rank(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(q * len(ordered)) - 1)], 3)


@pytest.fixture
def scripted_mix(
    client: TestClient, stub: StubModel, fake_steps, masked_inbound, real_chain, fixed_ids, today,
) -> TestClient:
    """Seven requests: resolved, denied and department-scoped bindings, a denied and an
    allowed client tool call, a signature block and an injection block."""
    stub.add(_query(SALARY_SQL), text("Your salary is {x1} PLN."))                   # 1 anna: resolved
    assert _ask(client, "What is my salary?").headers["x-acl-verdict"] == "allow"
    stub.add(_query(CEO_SQL), text("The CEO earns {x1} PLN."))                      # 2 anna: denied
    assert _ask(client, "What does the CEO earn?").json()["choices"][0]["message"]["content"] == \
        "The CEO earns [UNAVAILABLE] PLN."
    stub.add(_query(DEPARTMENT_SQL, "list"), text("Your team: {x1}"))              # 3 marek: resolved
    assert _ask(client, "Who is in my team?", MAREK).headers["x-acl-verdict"] == "allow"
    stub.add(tool_call("send_email", {"to": "x@evil.com", "body": "hi"}))           # 4 anna: tool denied
    assert _ask(client, "Email the report.", tools=SEND_EMAIL).headers["x-acl-verdict"] == "block"
    stub.add(tool_call("send_email", {"to": "anna.zielinska@company.pl", "body": "hi"}))  # 5 marek: tool allowed
    assert _ask(client, "Email Anna.", MAREK, tools=SEND_EMAIL).headers["x-acl-verdict"] == "allow"
    assert _ask(client, f"Run this: {PICKLE}").headers["x-acl-verdict"] == "block"  # 6 anna: signature
    assert _ask(client, INJECTION_PHRASE).headers["x-acl-verdict"] == "block"      # 7 anna: injection
    return client


def test_new_metrics_keys_after_a_scripted_mix(scripted_mix: TestClient, audit_records) -> None:
    m = scripted_mix.get("/metrics").json()
    assert set(m) == SECTIONS | NEW_SECTIONS

    assert m["blocks_by_signature_category"] == {"unsafe_deserialization": 1}
    assert m["blocks_by_user"] == {"anna": 3}
    assert m["binding_outcomes_by_role_and_table"] == {
        "intern": {"salaries": {"resolved": 1, "denied": 1, "rejected": 0, "empty": 0, "error": 0}},
        "sales_lead": {"employees": {"resolved": 1, "denied": 0, "rejected": 0, "empty": 0, "error": 0}},
    }
    assert m["tool_decisions_by_tool"] == {"send_email": {"allow": 1, "deny": 1}}

    over_time = m["blocks_over_time"]
    assert len(over_time) == 60
    assert over_time[0]["minute"] == "2026-10-03T11:01:00+00:00"
    assert over_time[-1] == {"minute": "2026-10-03T12:00:00+00:00", "requests": 7, "blocks": 3}
    assert sum(b["requests"] for b in over_time[:-1]) == 0

    records = audit_records()
    latency = m["latency_by_step"]
    assert list(latency)[-1] == "total"
    steps = {s for r in records for s in r["step_latency_ms"]}
    assert set(latency) == steps | {"total"}
    for step in steps:
        values = [r["step_latency_ms"][step] for r in records if step in r["step_latency_ms"]]
        assert latency[step] == {"median_ms": _nearest_rank(values, 0.5), "p95_ms": _nearest_rank(values, 0.95),
                                 "count": len(values)}
    totals = [r["total_latency_ms"] for r in records]
    assert latency["total"]["count"] == 7
    assert latency["total"]["median_ms"] == _nearest_rank(totals, 0.5)
    assert latency["total"]["median_ms"] <= latency["total"]["p95_ms"]


def test_t1_keys_are_unchanged_by_the_new_sections(scripted_mix: TestClient) -> None:
    m = scripted_mix.get("/metrics").json()
    assert m["requests_by_verdict"] == {"allow": 4, "redact": 0, "block": 3, "log": 0}
    assert m["blocks_by_control"] == {"injection": 1, "signatures": 1, "tool_authz.allow_pattern": 1}
    assert set(m["tokens_and_cost_by_user"]["users"]) == {"anna", "marek"}
    assert [r["user"] for r in m["last_requests"]] == ["anna", "anna", "marek", "anna", "marek", "anna", "anna"]
    assert set(m["last_requests"][0]) == {"time", "request_id", "user", "role", "verdict", "control", "reason"}


def test_new_sections_hold_no_values(scripted_mix: TestClient) -> None:
    body = scripted_mix.get("/metrics").text
    for raw in ("6200", "6,200", "Marek Wojcik", "x@evil.com", "katarzyna"):
        assert raw not in body


def test_signature_ids_missing_from_the_feed_count_as_unknown(audit_log: Path) -> None:
    from gateway.inbound.signatures import parse_feed

    feed = parse_feed((REPO_ROOT / "signatures.json").read_bytes())
    m = audit_metrics([dataclasses.asdict(_record(1, "block", decisions=[
        Decision("input_checks", "signatures", "block", "Matched attack signature(s) SIG-GONE-9 (feed x); blocked."),
    ]))], POLICY, now=NOW, feed=feed)
    assert m["blocks_by_signature_category"] == {"unknown": 1}


def test_one_request_counts_once_per_category(audit_log: Path) -> None:
    from gateway.inbound.signatures import parse_feed

    feed = parse_feed((REPO_ROOT / "signatures.json").read_bytes())
    deser = [s.id for s in feed.signatures if s.category == "unsafe_deserialization"]
    reason = "Matched attack signature(s) " + ", ".join(deser[:2]) + " (feed x); blocked."
    m = audit_metrics([dataclasses.asdict(_record(1, "block", decisions=[
        Decision("input_checks", "signatures", "block", reason),
        Decision("output_filter", "signatures", "block", reason),
    ]))], POLICY, now=NOW, feed=feed)
    assert m["blocks_by_signature_category"] == {"unsafe_deserialization": 1}


def test_blocks_over_time_ignores_records_older_than_an_hour(audit_log: Path) -> None:
    old = dataclasses.replace(_record(1, "block"), timestamp="2026-10-03T10:59:59+00:00")
    edge = dataclasses.replace(_record(2, "block"), timestamp="2026-10-03T11:01:00+00:00")
    m = _metrics(old, edge)
    assert sum(b["blocks"] for b in m["blocks_over_time"]) == 1
    assert m["blocks_over_time"][0]["blocks"] == 1


def test_latency_percentiles_use_nearest_rank(audit_log: Path) -> None:
    records = [_record(i, step_latency_ms={"authenticate": float(i)}, total_latency_ms=float(i)) for i in range(1, 21)]
    m = _metrics(*records)
    assert m["latency_by_step"]["authenticate"] == {"median_ms": 10.0, "p95_ms": 19.0, "count": 20}
    assert m["latency_by_step"]["total"] == {"median_ms": 10.0, "p95_ms": 19.0, "count": 20}
