"""Audit log and telemetry. Spec section 4 step 10, section 6 'audit', section 13 (AuditRecord), I8, I17.

Owner: Person 4.
"""
from __future__ import annotations

import csv
import dataclasses
import io
import json
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway import pipeline
from gateway.agency import loop
from gateway.audit import export_csv, find_request_values, read_audit, write_audit
from gateway.binding.authorizer import authorize
from gateway.binding.executor import execute
from gateway.binding.sql_validator import validate_sql
from gateway.inbound.masker import mask_messages
from gateway.llm.client import StubModel, text, tool_call
from gateway.models import (
    AuditRecord,
    Binding,
    BindingOutcome,
    Decision,
    SanitizedRequest,
    ToolDecision,
    Vault,
)
from gateway.policy.loader import load_policy
from gateway.telemetry import StepTimer
from tests.conftest import INJECTION_PHRASE

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY = load_policy(REPO_ROOT / "policy.yaml")
ANNA = {"Authorization": "Bearer demo-anna"}
API_KEY = "sk-proj-Abc123Def456Ghi789Jkl012Mno345"
SALARY_SQL = "SELECT salary FROM salaries WHERE employee_id = :current_user"


def _ask(client: TestClient, content: str, headers: dict[str, str] | None = None):
    payload = {"model": "qwen2.5:3b", "messages": [{"role": "user", "content": content}]}
    return client.post("/v1/chat/completions", json=payload, headers=ANNA if headers is None else headers)


def _record(**fields: Any) -> AuditRecord:
    return AuditRecord(request_id="r1", timestamp="2026-10-03T12:00:00+00:00", policy_version="p",
                       feed_version="f", verdict="allow", **fields)


def _binding(value: Any, name: str = "{x1}", expect: str = "scalar") -> Binding:
    return Binding(name=name, sql=SALARY_SQL, purpose="t", expect=expect,  # type: ignore[arg-type]
                   status="resolved", value=value)


def _outcome(**fields: Any) -> BindingOutcome:
    base = dict(name="{x1}", sql=SALARY_SQL, purpose="t", status="resolved", label="sensitive", disclosed=False,
                reason="", tables=["salaries"], columns=["salary"], rows=1, truncated=False, latency_ms=1.0)
    return BindingOutcome(**{**base, **fields})


@pytest.fixture
def masked_inbound(monkeypatch: pytest.MonkeyPatch) -> None:
    """inspect_inbound has not landed: mask user messages with the real masker, nothing else."""
    def inspect(req: Any, p: Any, policy: Any, cache: Any) -> Any:
        messages, vault, _ = mask_messages([m.model_dump(exclude_none=True) for m in req.messages], policy)
        return SanitizedRequest(messages=messages, tools=list(req.tools or [])), vault, []
    monkeypatch.setattr(pipeline, "inspect_inbound", inspect)


@pytest.fixture
def real_chain(db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The real validate -> authorize -> execute chain on the seeded database."""
    monkeypatch.setattr(loop, "validate_sql", validate_sql)
    monkeypatch.setattr(loop, "authorize", authorize)
    monkeypatch.setattr(loop, "execute", execute)


@pytest.fixture
def fixed_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """Request IDs and timestamps without random digits, so a substring search of the log is exact."""
    import uuid

    monkeypatch.setattr(uuid, "uuid4", lambda: uuid.UUID(int=0))
    real = pipeline._new_record

    def new_record(policy: Any, feed: Any) -> AuditRecord:
        return dataclasses.replace(real(policy, feed), timestamp="2026-10-03T12:00:00+00:00")

    monkeypatch.setattr(pipeline, "_new_record", new_record)


# ---------------------------------------------------------------------------
# One record per request
# ---------------------------------------------------------------------------


def test_one_record_per_request_including_a_401_and_a_block(
    client: TestClient, stub: StubModel, fake_steps, audit_records
) -> None:
    stub.add(text("Paris."))
    allowed = _ask(client, "Capital of France?")
    unauthorized = _ask(client, "Hi", headers={"Authorization": "Bearer nope"})
    blocked = _ask(client, INJECTION_PHRASE)

    assert (allowed.status_code, unauthorized.status_code, blocked.status_code) == (200, 401, 200)
    records = audit_records()
    assert [r["verdict"] for r in records] == ["allow", "block", "block"]
    assert len({r["request_id"] for r in records}) == 3
    assert (records[0]["request_id"], records[2]["request_id"]) == (
        allowed.headers["x-acl-request-id"], blocked.headers["x-acl-request-id"])
    assert records[1]["user_id"] is None
    assert any(d["verdict"] == "block" for d in records[2]["decisions"])


def test_record_has_every_field_the_spec_lists(client: TestClient, stub: StubModel, fake_steps, audit_records) -> None:
    stub.add(tool_call("query_data", {"sql": "SELECT 1", "purpose": "t", "expect": "scalar"}), text("{x1}"))
    _ask(client, "Count?")
    (r,) = audit_records()
    for key in ("request_id", "timestamp", "policy_version", "feed_version", "user_id", "role", "department",
                "ai_data_policy", "answer_model", "judge_model", "decisions", "bindings", "tool_decisions",
                "tool_iterations", "disabled_controls", "prompt_tokens", "completion_tokens", "judge_tokens",
                "cost_usd", "step_latency_ms", "total_latency_ms", "verdict", "prompt_text"):
        assert key in r, key
    assert r["policy_version"] == POLICY.version_hash
    assert r["tool_iterations"] == 1
    assert r["prompt_tokens"] > 0 and r["completion_tokens"] > 0
    assert set(r["step_latency_ms"]) >= {"authenticate", "model_and_budget", "model_and_tool_loop", "record"}
    assert r["total_latency_ms"] >= max(r["step_latency_ms"].values())
    (b,) = r["bindings"]
    assert b["name"] == "{x1}" and b["status"] == "resolved"
    assert "value" not in b


# ---------------------------------------------------------------------------
# No values in the log file
# ---------------------------------------------------------------------------


def test_filled_salary_and_masked_api_key_never_reach_the_log_file(
    client: TestClient, stub: StubModel, fake_steps, masked_inbound, real_chain, fixed_ids,
    audit_log: Path,
) -> None:
    stub.add(tool_call("query_data", {"sql": SALARY_SQL, "purpose": "own salary", "expect": "scalar"}),
             text("Your salary is {x1} PLN."))
    r = _ask(client, f"My key is {API_KEY}. What is my salary?")

    assert r.json()["choices"][0]["message"]["content"] == "Your salary is 6200 PLN."  # it was filled
    log_text = audit_log.read_text(encoding="utf-8")
    for raw in ("6200", "6,200", API_KEY):
        assert raw not in log_text
    (record,) = [json.loads(line) for line in log_text.splitlines()]
    assert record["verdict"] == "allow"
    assert "[SECRET_1]" in record["prompt_text"] or "[REDACTED" in record["prompt_text"]


def test_model_echoing_the_value_into_the_purpose_withholds_the_details(
    client: TestClient, stub: StubModel, fake_steps, masked_inbound, real_chain, fixed_ids,
    audit_log: Path,
) -> None:
    sql = "SELECT salary FROM salaries WHERE employee_id = :current_user AND salary > 6199"
    stub.add(tool_call("query_data", {"sql": sql, "purpose": "check it is 6,200", "expect": "scalar"}),
             text("{x1}"))
    _ask(client, "Salary?")

    log_text = audit_log.read_text(encoding="utf-8")
    assert "6200" not in log_text and "6,200" not in log_text and "6199" not in log_text
    (record,) = [json.loads(line) for line in log_text.splitlines()]
    assert record["verdict"] == "allow"  # the answer still went out; only the log copy is cut down
    assert any(d["control"] == "audit.guard" for d in record["decisions"])
    assert [b["status"] for b in record["bindings"]] == ["resolved"]


def test_prompt_text_is_masked_by_default(
    client: TestClient, stub: StubModel, fake_steps, masked_inbound, audit_records
) -> None:
    stub.add(text("Noted."))
    _ask(client, f"Use {API_KEY} and mail anna.zielinska@company.pl")
    (record,) = audit_records()
    assert record["prompt_text"].startswith("Use ")
    assert API_KEY not in record["prompt_text"]
    assert "anna.zielinska@company.pl" not in record["prompt_text"]


def test_prompt_text_is_not_logged_when_log_prompt_text_is_none(
    policy: Path, client: TestClient, stub: StubModel, fake_steps, masked_inbound, audit_records
) -> None:
    policy.write_text(policy.read_text(encoding="utf-8").replace("log_prompt_text: masked", "log_prompt_text: none"),
                      encoding="utf-8")
    stub.add(text("Noted."))
    _ask(client, "A question I would rather not have logged")
    (record,) = audit_records()
    assert record["prompt_text"] is None
    assert "rather not" not in json.dumps(record)


def test_unmasked_secret_in_the_prompt_is_still_redacted_in_the_log(
    client: TestClient, stub: StubModel, fake_steps, audit_log: Path
) -> None:
    stub.add(text("Noted."))  # fake_steps inbound masks nothing
    _ask(client, f"Key {API_KEY}")
    assert API_KEY not in audit_log.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("written", ["6200", "6,200", "6 200", "6.200", "6200.0", "salary=6200;"])
def test_guard_finds_a_binding_value_in_any_spelling(written: str) -> None:
    record = _record(decisions=[Decision("s", "c", "allow", f"saw {written}")])
    assert find_request_values(record, bindings={"{x1}": _binding(6200)}) == ["decisions[0].reason"]


def test_guard_finds_a_vault_value_case_insensitively() -> None:
    vault = Vault()
    vault.add_mask("[SECRET_1]", API_KEY)
    record = _record(bindings=[_outcome(purpose="leak " + API_KEY.upper())])
    assert find_request_values(record, vault=vault) == ["bindings[0].purpose"]


def test_guard_finds_one_cell_of_a_list_value() -> None:
    table = "| name | city |\n| --- | --- |\n| Katarzyna Nowak | Gdansk |"
    record = _record(tool_decisions=[ToolDecision("send_email", "deny", "egress", "to Katarzyna Nowak")])
    assert find_request_values(record, bindings={"{x1}": _binding(table, expect="list")}) == [
        "tool_decisions[0].reason"]


def test_guard_ignores_values_inside_longer_tokens_and_short_values() -> None:
    record = _record(decisions=[Decision("s", "c", "allow", "id 162001 at x1 for 25 rows")],
                     prompt_text="ok")
    bindings = {"{x1}": _binding(6200), "{x2}": _binding(25, "{x2}"), "{x3}": _binding("ok", "{x3}")}
    assert find_request_values(record, bindings=bindings) == []


def test_guard_does_not_check_identity_fields() -> None:
    record = _record(user_id="anna", role="intern")
    assert find_request_values(record, bindings={"{x1}": _binding("anna")}) == []


def test_write_audit_withholds_details_when_the_guard_finds_a_value(audit_log: Path) -> None:
    record = _record(
        user_id="anna", prompt_tokens=10,
        decisions=[Decision("tool_loop", "x", "allow", "value 6200")],
        bindings=[_outcome(purpose="it is 6200")],
        tool_decisions=[ToolDecision("send_email", "deny", "egress", "6200 left")],
        prompt_text="is it 6200?",
    )
    write_audit(record, POLICY, bindings={"{x1}": _binding(6200)})
    text_ = audit_log.read_text(encoding="utf-8")
    assert "6200" not in text_
    (saved,) = [json.loads(line) for line in text_.splitlines()]
    assert (saved["request_id"], saved["user_id"], saved["verdict"], saved["prompt_tokens"]) == ("r1", "anna", "allow", 10)
    assert saved["prompt_text"] is None
    assert saved["bindings"][0]["status"] == "resolved" and saved["bindings"][0]["purpose"] == ""
    assert saved["tool_decisions"][0]["verdict"] == "deny" and saved["tool_decisions"][0]["reason"] == ""
    assert [d["control"] for d in saved["decisions"]] == ["audit.guard"]


def test_write_audit_writes_clean_records_unchanged(audit_log: Path) -> None:
    record = _record(decisions=[Decision("s", "c", "allow", "fine")], prompt_text="hello")
    write_audit(record, POLICY, bindings={"{x1}": _binding(6200)})
    (saved,) = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert saved == json.loads(json.dumps(dataclasses.asdict(record)))


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------


def test_csv_export_has_a_header_and_one_row_per_request(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.fallback = text("Ok.")
    first = _ask(client, "Hi").headers["x-acl-request-id"]
    assert _ask(client, "Hi", headers={"Authorization": "Bearer nope"}).status_code == 401
    last = _ask(client, INJECTION_PHRASE).headers["x-acl-request-id"]
    r = client.get("/audit/export?format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:3] == ["request_id", "timestamp", "verdict"]
    assert "prompt_text" in rows[0]
    assert len(rows) == 4
    assert (rows[1][0], rows[3][0]) == (first, last)
    assert [row[2] for row in rows[1:]] == ["allow", "block", "block"]


def test_csv_export_neutralises_spreadsheet_formulas() -> None:
    out = export_csv([{"request_id": "r", "prompt_text": "=HYPERLINK(\"x\")", "decisions": []}])
    (row,) = list(csv.DictReader(io.StringIO(out)))
    assert row["prompt_text"].startswith("'=")


def test_csv_export_time_range(audit_log: Path) -> None:
    for i, ts in enumerate(["2026-10-01T00:00:00+00:00", "2026-10-02T00:00:00+00:00", "2026-10-03T00:00:00+00:00"]):
        write_audit(dataclasses.replace(_record(), request_id=f"r{i}", timestamp=ts), POLICY)
    from datetime import datetime, timezone
    records = read_audit(POLICY, datetime(2026, 10, 2, tzinfo=timezone.utc), datetime(2026, 10, 3, tzinfo=timezone.utc))
    assert [r["request_id"] for r in records] == ["r1"]


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


def test_step_timer_times_each_step_including_one_that_raises() -> None:
    timer = StepTimer()
    with timer.step("a"):
        time.sleep(0.01)
    with pytest.raises(RuntimeError), timer.step("b"):
        raise RuntimeError
    with timer.step("a"):
        pass
    assert set(timer.steps) == {"a", "b"}
    assert timer.steps["a"] >= 10
    assert timer.total_ms() >= timer.steps["a"] + timer.steps["b"]
