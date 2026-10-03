"""Budgets: tokens per day, requests per minute, cost per day (state.db). Spec section 4 steps 2 and 10,
section 6 'budgets', I18. Owner: Person 4.

Every test gets its own state.db (``ACL_STATE_PATH``, conftest ``state_db``).
"""
from __future__ import annotations

import copy
import importlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from gateway import budget
from gateway.budget import admit_request, check_model_and_budget, record_usage
from gateway.llm.client import StubModel, text, tool_call
from gateway.models import Policy, Principal
from gateway.policy.loader import parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
ANNA = Principal("anna", "intern", "sales", "deny")
MAREK = Principal("marek", "sales_lead", "sales", "allow")
PIOTR = Principal("piotr", "hr_manager", "hr", "allow")
NOON = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc).timestamp()


def _data() -> dict[str, Any]:
    return copy.deepcopy(yaml.safe_load((REPO_ROOT / "policy.yaml").read_text(encoding="utf-8")))


def _policy(data: dict[str, Any] | None = None) -> Policy:
    return parse_policy(yaml.safe_dump(data or _data()).encode("utf-8"))


POLICY = _policy()


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """``clock[0]`` is the budget module's current time (seconds since the epoch)."""
    now = [NOON]
    monkeypatch.setattr(budget, "_now", lambda: now[0])
    return now


def _check(p: Principal = ANNA, estimate: int = 100, policy: Policy = POLICY, model: str = "llama3.2"):
    return check_model_and_budget(p, model, estimate, policy)


# ---------------------------------------------------------------------------
# Tokens and cost per day
# ---------------------------------------------------------------------------


def test_request_within_budget_passes(clock: list[float]) -> None:
    d = _check()
    assert d.verdict == "allow"
    assert d.stage == "model_and_budget"


def test_usage_up_to_the_daily_token_limit_blocks_the_next_call(clock: list[float]) -> None:
    record_usage(ANNA, 19_950, "llama3.2", POLICY)
    assert _check(estimate=50).verdict == "allow"
    d = _check(estimate=51)
    assert d.verdict == "block"
    assert d.control == "budgets.tokens_per_day"
    assert "19" not in d.reason and "20" not in d.reason  # no counters or limits in reasons


def test_estimate_alone_above_the_limit_is_blocked(clock: list[float]) -> None:
    assert _check(estimate=20_001).verdict == "block"


def test_usage_is_counted_per_user(clock: list[float]) -> None:
    record_usage(ANNA, 20_000, "llama3.2", POLICY)
    assert _check(ANNA).verdict == "block"
    assert _check(MAREK).verdict == "allow"


def test_daily_cost_limit_blocks(clock: list[float]) -> None:
    data = _data()
    data["budgets"]["default"]["tokens_per_day"] = 10_000_000
    data["budgets"]["default"]["cost_per_day_usd"] = 0.01
    data["pricing_per_1k_tokens"]["llama3.2"] = 0.001
    policy = _policy(data)
    record_usage(ANNA, 9_000, "llama3.2", policy)  # 0.009 USD
    assert _check(estimate=1_000, policy=policy).verdict == "allow"  # exactly 0.010
    d = _check(estimate=1_001, policy=policy)
    assert d.verdict == "block"
    assert d.control == "budgets.cost_per_day_usd"


def test_cost_uses_the_price_of_the_model_that_was_called(clock: list[float]) -> None:
    data = _data()
    data["budgets"]["default"]["tokens_per_day"] = 10_000_000
    data["budgets"]["default"]["cost_per_day_usd"] = 0.01
    policy = _policy(data)
    record_usage(ANNA, 16_000, "gpt-4o-mini", policy)  # 0.0096 USD at 0.0006 / 1k
    assert _check(estimate=1_000, model="qwen2.5:1.5b", policy=policy).verdict == "allow"  # +0.0001
    assert _check(estimate=1_000, model="gpt-4o-mini", policy=policy).verdict == "block"  # +0.0006


def test_unpriced_model_costs_nothing(clock: list[float]) -> None:
    data = _data()
    data["budgets"]["default"]["tokens_per_day"] = 10_000_000
    data["budgets"]["default"]["cost_per_day_usd"] = 0.0
    data["models"]["allowed"].append({"name": "free-model"})
    policy = _policy(data)
    record_usage(ANNA, 1_000_000, "free-model", policy)
    assert _check(estimate=1_000, model="free-model", policy=policy).verdict == "allow"


def test_hr_manager_override_raises_only_the_keys_it_sets(clock: list[float]) -> None:
    record_usage(ANNA, 50_000, "llama3.2", POLICY)
    record_usage(PIOTR, 50_000, "llama3.2", POLICY)
    assert _check(ANNA).verdict == "block"  # default 20,000
    assert _check(PIOTR).verdict == "allow"  # hr_manager 200,000
    for _ in range(10):  # requests_per_minute still comes from the default
        assert admit_request(PIOTR, POLICY).verdict == "allow"
    assert admit_request(PIOTR, POLICY).verdict == "block"


def test_role_without_override_uses_the_profile_default(clock: list[float]) -> None:
    data = _data()
    del data["budgets"]["default"]["tokens_per_day"]
    data["profile"] = "balanced"  # profile default 50,000
    policy = _policy(data)
    record_usage(ANNA, 49_900, "llama3.2", policy)
    assert _check(estimate=100, policy=policy).verdict == "allow"
    assert _check(estimate=101, policy=policy).verdict == "block"


def test_day_boundary_is_the_utc_date(clock: list[float]) -> None:
    clock[0] = datetime(2026, 10, 3, 23, 59, 59, tzinfo=timezone.utc).timestamp()
    record_usage(ANNA, 20_000, "llama3.2", POLICY)
    assert _check().verdict == "block"
    clock[0] += 1  # 00:00:00 UTC on the next day
    assert _check().verdict == "allow"


# ---------------------------------------------------------------------------
# Requests per minute
# ---------------------------------------------------------------------------


def test_the_eleventh_request_in_a_minute_is_blocked(clock: list[float]) -> None:
    for i in range(10):
        clock[0] = NOON + i
        assert admit_request(ANNA, POLICY).verdict == "allow"
    d = admit_request(ANNA, POLICY)
    assert d.verdict == "block"
    assert d.control == "budgets.requests_per_minute"
    assert admit_request(MAREK, POLICY).verdict == "allow"


def test_per_minute_window_is_sliding(clock: list[float]) -> None:
    for i in range(10):
        clock[0] = NOON + i * 5  # 12:00:00 ... 12:00:45
        admit_request(ANNA, POLICY)
    clock[0] = NOON + 59.9
    assert admit_request(ANNA, POLICY).verdict == "block"
    clock[0] = NOON + 60.0  # the first request has left the window; only one slot opened
    assert admit_request(ANNA, POLICY).verdict == "allow"
    assert admit_request(ANNA, POLICY).verdict == "block"


def test_blocked_requests_do_not_count_against_the_window(clock: list[float]) -> None:
    for _ in range(10):
        admit_request(ANNA, POLICY)
    for _ in range(5):
        assert admit_request(ANNA, POLICY).verdict == "block"
    clock[0] = NOON + 60
    for _ in range(10):
        assert admit_request(ANNA, POLICY).verdict == "allow"


def test_model_calls_inside_a_request_are_not_requests(clock: list[float]) -> None:
    for _ in range(10):
        admit_request(ANNA, POLICY)
    for _ in range(5):  # loop iterations and the judge of the tenth request
        assert _check().verdict == "allow"


# ---------------------------------------------------------------------------
# Judge tokens, persistence, store
# ---------------------------------------------------------------------------


def test_judge_tokens_are_counted_when_count_judge_tokens_is_true(clock: list[float]) -> None:
    record_usage(ANNA, 20_000, "qwen2.5:1.5b", POLICY, judge=True)
    assert _check().verdict == "block"


def test_judge_tokens_are_not_counted_when_count_judge_tokens_is_false(clock: list[float]) -> None:
    data = _data()
    data["budgets"]["count_judge_tokens"] = False
    policy = _policy(data)
    record_usage(ANNA, 20_000, "qwen2.5:1.5b", policy, judge=True)
    assert _check(policy=policy).verdict == "allow"
    record_usage(ANNA, 20_000, "llama3.2", policy)  # answer tokens always count
    assert _check(policy=policy).verdict == "block"


def test_counters_survive_a_gateway_restart(clock: list[float], state_db: Path) -> None:
    record_usage(ANNA, 20_000, "llama3.2", POLICY)
    for _ in range(10):
        admit_request(ANNA, POLICY)
    reloaded = importlib.reload(budget)  # a fresh module: no in-memory state carries over
    reloaded._now = lambda: clock[0]
    assert reloaded.check_model_and_budget(ANNA, "llama3.2", 1, POLICY).verdict == "block"
    assert reloaded.admit_request(ANNA, POLICY).verdict == "block"
    with sqlite3.connect(state_db) as conn:  # on disk, not in memory
        assert conn.execute("SELECT tokens FROM usage WHERE user_id = 'anna'").fetchone() == (20_000,)


def test_store_path_comes_from_the_policy(
    clock: list[float], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ACL_STATE_PATH")
    data = _data()
    data["budgets"]["store"] = str(tmp_path / "budgets.db")
    record_usage(ANNA, 5, "llama3.2", _policy(data))
    assert (tmp_path / "budgets.db").exists()


def test_store_never_uses_the_data_database(
    clock: list[float], db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACL_STATE_PATH", str(db))
    before = db.read_bytes()
    assert _check().verdict == "block"
    assert admit_request(ANNA, POLICY).verdict == "block"
    with pytest.raises(ValueError):
        record_usage(ANNA, 5, "llama3.2", POLICY)
    assert db.read_bytes() == before


def test_unusable_store_fails_closed(clock: list[float], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACL_STATE_PATH", str(tmp_path))  # a directory
    d = _check()
    assert d.verdict == "block"
    assert d.reason == "Budget check failed."
    assert admit_request(ANNA, POLICY).verdict == "block"


@pytest.mark.parametrize("estimate", [-1, 1.5, "100", None, True])
def test_invalid_estimate_is_blocked(clock: list[float], estimate: Any) -> None:
    assert _check(estimate=estimate).verdict == "block"


@pytest.mark.parametrize("tokens", [-1, 1.5, None])
def test_invalid_usage_is_refused(clock: list[float], tokens: Any) -> None:
    with pytest.raises(ValueError):
        record_usage(ANNA, tokens, "llama3.2", POLICY)


# ---------------------------------------------------------------------------
# Through the pipeline
# ---------------------------------------------------------------------------

ANNA_KEY = {"Authorization": "Bearer demo-anna"}


def _ask(client: TestClient, content: str = "Hello?"):
    payload = {"model": "llama3.2", "messages": [{"role": "user", "content": content}]}
    return client.post("/v1/chat/completions", json=payload, headers=ANNA_KEY)


def test_pipeline_request_within_budget_passes_and_is_charged(
    clock: list[float], client: TestClient, stub: StubModel, fake_steps, state_db: Path
) -> None:
    stub.add(text("Hi."))
    r = _ask(client)
    assert r.status_code == 200
    assert r.headers["x-acl-verdict"] == "allow"
    with sqlite3.connect(state_db) as conn:
        (tokens,) = conn.execute("SELECT tokens FROM usage WHERE user_id = 'anna'").fetchone()
    assert tokens == r.json()["usage"]["total_tokens"]


def test_pipeline_request_after_the_limit_is_blocked_before_any_model_call(
    clock: list[float], client: TestClient, stub: StubModel, judge_stub: StubModel, fake_steps, audit_records
) -> None:
    record_usage(ANNA, 20_000, "llama3.2", POLICY)
    r = _ask(client)
    assert r.status_code == 200
    assert r.headers["x-acl-verdict"] == "block"
    assert stub.calls == []
    assert judge_stub.calls == []
    (record,) = audit_records()
    assert any(d["control"] == "budgets.tokens_per_day" and d["verdict"] == "block" for d in record["decisions"])


def test_pipeline_blocks_the_eleventh_request_in_a_minute(
    clock: list[float], client: TestClient, stub: StubModel, fake_steps
) -> None:
    stub.fallback = text("Hi.")
    verdicts = [_ask(client).headers["x-acl-verdict"] for _ in range(11)]
    assert verdicts == ["allow"] * 10 + ["block"]
    assert len(stub.calls) == 10


def test_pipeline_estimate_includes_max_tokens(
    clock: list[float], client: TestClient, stub: StubModel, fake_steps
) -> None:
    record_usage(ANNA, 20_000 - 400, "llama3.2", POLICY)  # the prompt fits, prompt + 512 does not
    assert _ask(client, "Hi").headers["x-acl-verdict"] == "block"
    assert stub.calls == []


def test_tool_loop_stops_when_a_call_exhausts_the_budget(
    clock: list[float], client: TestClient, stub: StubModel, fake_steps, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.agency import loop

    estimates: list[int] = []

    def spy(p: Principal, model: str, estimate: int, policy: Policy):
        estimates.append(estimate)
        return budget.check_model_and_budget(p, model, estimate, policy)

    monkeypatch.setattr(loop, "check_model_and_budget", spy)
    query = tool_call("query_data", {"sql": "SELECT 1", "purpose": "t", "expect": "scalar"})
    stub.add(query, text("Done."))
    assert _ask(client).headers["x-acl-verdict"] == "allow"  # learn the first loop call's estimate
    first_call = estimates[0]

    clock[0] += 86_400  # a new day: fresh counters and a fresh per-minute window
    record_usage(ANNA, 20_000 - first_call, "llama3.2", POLICY)  # exactly room for the first call
    stub.calls.clear()
    stub.add(query, text("Done."))
    r = _ask(client)
    assert r.headers["x-acl-verdict"] == "block"
    assert len(stub.calls) == 1  # its usage was recorded, so the second call was never made
