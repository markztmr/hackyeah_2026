"""GET /metrics, computed from the audit log; the dashboard's only data besides /policy/effective.

Spec section 12 'Dashboard panels', section 13. Owner: Person 4.
"""
from __future__ import annotations

import dataclasses
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
SECTIONS = {"requests_by_verdict", "blocks_by_control", "tokens_and_cost_by_user", "last_requests"}
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def _ask(client: TestClient, content: str, headers: dict[str, str] | None = None):
    payload = {"model": "qwen2.5:3b", "messages": [{"role": "user", "content": content}]}
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
    client: TestClient, stub: StubModel, fake_steps, masked_inbound, real_chain, fixed_ids, today,
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
    assert set(m) == SECTIONS
    assert m["requests_by_verdict"] == {"allow": 1, "redact": 0, "block": 1, "log": 0}
    assert m["blocks_by_control"] == {"injection": 1}

    newest, oldest = m["last_requests"]
    assert (oldest["user"], oldest["verdict"], oldest["control"], oldest["reason"]) == ("anna", "allow", None, None)
    assert (newest["user"], newest["verdict"], newest["control"]) == ("anna", "block", "injection")
    assert newest["reason"].endswith(".") and newest["reason"][0].isupper()
    assert set(newest) == {"time", "request_id", "user", "role", "verdict", "control", "reason"}

    anna = m["tokens_and_cost_by_user"]["users"]["anna"]
    assert anna["tokens"] == allowed.json()["usage"]["total_tokens"] + blocked.json()["usage"]["total_tokens"]
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
    assert set(m) == SECTIONS
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
