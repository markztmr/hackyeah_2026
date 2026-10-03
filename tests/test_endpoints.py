"""Endpoints from spec section 13 other than the pipeline itself. Owner: Person 1."""
from __future__ import annotations

import csv
import io
import os
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway.audit import export_csv
from gateway.llm import client as llm
from gateway.llm.client import StubModel, text

ANNA = {"Authorization": "Bearer demo-anna"}
BODY = {"model": "llama3.2", "messages": [{"role": "user", "content": "Hi"}]}


def _bump(path: Path, content: str) -> None:
    old = path.stat().st_mtime_ns
    path.write_text(content, encoding="utf-8")
    os.utime(path, ns=(old + 2_000_000_000, old + 2_000_000_000))


# ---------------------------------------------------------------------------
# /v1/models
# ---------------------------------------------------------------------------


def test_models_lists_the_allowed_models_in_openai_format(client: TestClient) -> None:
    r = client.get("/v1/models", headers=ANNA)
    assert r.status_code == 200
    body = r.json()
    assert body["object"] == "list"
    assert [m["id"] for m in body["data"]] == ["llama3.2", "qwen2.5:3b", "qwen2.5:1.5b"]
    assert all(m["object"] == "model" for m in body["data"])


def test_models_needs_a_valid_key(client: TestClient) -> None:
    assert client.get("/v1/models").status_code == 401
    assert client.get("/v1/models", headers={"Authorization": "Bearer nope"}).status_code == 401


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


def test_health_reports_versions_model_reachability_and_no_error(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, policy: Path
) -> None:
    monkeypatch.setattr(llm, "ping", lambda purpose, pol, timeout_s=1.0: purpose == "answer")
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert len(body["policy"]["version"]) == 64
    assert body["policy"]["error"] is None
    assert body["feed"]["version"]
    assert body["feed"]["error"] is None
    assert body["models"]["answer"] == {"name": "llama3.2", "base_url": "http://localhost:11434/v1", "reachable": True}
    assert body["models"]["judge"]["reachable"] is False
    assert body["status"] == "degraded"


def test_health_shows_the_last_reload_error_and_keeps_the_old_version(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, policy: Path
) -> None:
    monkeypatch.setattr(llm, "ping", lambda purpose, pol, timeout_s=1.0: True)
    before = client.get("/health").json()
    assert before["status"] == "ok"
    _bump(policy, "users: [unclosed\n")

    after = client.get("/health").json()
    assert after["policy"]["error"]
    assert after["policy"]["version"] == before["policy"]["version"]
    assert after["status"] == "degraded"


def test_health_never_contains_api_keys(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(llm, "ping", lambda purpose, pol, timeout_s=1.0: True)
    assert "demo-anna" not in client.get("/health").text


# ---------------------------------------------------------------------------
# /metrics
# ---------------------------------------------------------------------------


def test_metrics_count_requests_by_verdict_with_step_latency(
    client: TestClient, stub: StubModel, fake_steps
) -> None:
    stub.add(text("ok"))
    client.post("/v1/chat/completions", json=BODY, headers=ANNA)
    client.post("/v1/chat/completions", json=BODY, headers={"Authorization": "Bearer nope"})

    m = client.get("/metrics").json()
    assert m["requests"] == 2
    assert m["verdicts"] == {"allow": 1, "block": 1}
    assert m["steps"]["model_and_tool_loop"]["count"] == 1
    assert m["total"]["median_ms"] is not None


# ---------------------------------------------------------------------------
# /policy/effective and /policy/reload
# ---------------------------------------------------------------------------


def test_policy_effective_lists_controls_without_api_keys(client: TestClient) -> None:
    r = client.get("/policy/effective")
    assert r.status_code == 200
    body = r.json()
    assert body["controls"]["prompt_controls.injection.mode"] == {"value": "block", "source": "explicit"}
    assert "demo-anna" not in r.text


def test_policy_reload_succeeds_on_a_valid_file(client: TestClient, policy: Path) -> None:
    policy.write_text(policy.read_text(encoding="utf-8").replace("max_rows: 50", "max_rows: 40"), encoding="utf-8")
    r = client.post("/policy/reload")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert client.get("/policy/effective").json()["controls"]["sql_controls.max_rows"]["value"] == 40


def test_policy_reload_reports_the_validation_error_and_keeps_the_old_policy(client: TestClient, policy: Path) -> None:
    version = client.get("/policy/effective").json()["version"]
    policy.write_text(policy.read_text(encoding="utf-8") + "\naudit_off: true\n", encoding="utf-8")
    r = client.post("/policy/reload")
    assert r.status_code == 422
    assert r.json()["ok"] is False
    assert "audit_off" in r.json()["policy"]["error"]
    assert client.get("/policy/effective").json()["version"] == version


def test_invalid_feed_is_reported_by_reload(client: TestClient, policy: Path) -> None:
    (policy.parent / "signatures.json").write_text("{not json", encoding="utf-8")
    r = client.post("/policy/reload")
    assert r.status_code == 422
    assert r.json()["feed"]["error"]


# ---------------------------------------------------------------------------
# /audit/export
# ---------------------------------------------------------------------------


def test_audit_export_returns_one_csv_row_per_request(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(text("ok"))
    ok = client.post("/v1/chat/completions", json=BODY, headers=ANNA)
    client.post("/v1/chat/completions", json=BODY, headers={"Authorization": "Bearer nope"})

    r = client.get("/audit/export?format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert [row["verdict"] for row in rows] == ["allow", "block"]
    assert rows[0]["request_id"] == ok.json()["id"]
    assert rows[0]["user_id"] == "anna"


def test_audit_export_filters_by_time_range(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(text("ok"))
    client.post("/v1/chat/completions", json=BODY, headers=ANNA)
    rows = list(csv.DictReader(io.StringIO(client.get("/audit/export?since=2999-01-01T00:00:00Z").text)))
    assert rows == []
    assert client.get("/audit/export?since=not-a-date").status_code == 422


def test_audit_export_rejects_other_formats(client: TestClient) -> None:
    assert client.get("/audit/export?format=json").status_code == 422


def test_csv_cells_that_look_like_formulas_are_escaped() -> None:
    record: dict[str, Any] = {
        "request_id": "=HYPERLINK(\"http://evil\")", "timestamp": "t", "verdict": "allow",
        "decisions": [], "bindings": [{"name": "{x1}", "status": "@SUM(A1)"}], "tool_decisions": [],
    }
    row = next(csv.DictReader(io.StringIO(export_csv([record]))))
    assert row["request_id"].startswith("'=")
    assert row["bindings"] == "{x1}: @SUM(A1)"  # not at the start of the cell, so harmless
