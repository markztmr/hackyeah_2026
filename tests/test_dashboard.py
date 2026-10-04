"""Streamlit dashboard: reads only the gateway's HTTP endpoints; survives a gateway that is down.

Spec section 12 'Dashboard panels'. Owner: Person 4.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
import streamlit as st
from streamlit.testing.v1 import AppTest

from dashboard import app as dashboard
from gateway.llm.client import StubModel, text
from tests.conftest import INJECTION_PHRASE
from tests.test_audit import fixed_ids, masked_inbound, real_chain  # noqa: F401 - fixtures
from tests.test_metrics import scripted_mix, today  # noqa: F401 - fixtures

REPO_ROOT = Path(__file__).resolve().parent.parent
APP = str(REPO_ROOT / "dashboard" / "app.py")
ANNA = {"Authorization": "Bearer demo-anna"}


@pytest.fixture(autouse=True)
def fresh_health_cache() -> None:
    """/health is cached by the dashboard; no test may see another test's gateway."""
    st.cache_data.clear()


def _table(at: AppTest, column: str) -> Any:
    """The one dataframe on the page that has this column."""
    (df,) = [d.value for d in at.dataframe if column in getattr(d.value, "columns", [])]
    return df


def _run() -> AppTest:
    at = AppTest.from_file(APP, default_timeout=20)
    at.run()
    assert not at.exception, at.exception
    return at


def _through(client: TestClient, monkeypatch: pytest.MonkeyPatch, missing: tuple[str, ...] = ()) -> None:
    """Route the dashboard's HTTP calls to the in-process gateway."""
    def get(url: str, params: Any = None, timeout: float = 0) -> httpx.Response:
        path = url.removeprefix(dashboard.GATEWAY_URL)
        if path in missing:
            return httpx.Response(404, json={"detail": "Not Found"})
        r = client.get(path, params=params)
        return httpx.Response(r.status_code, content=r.content, headers=dict(r.headers))
    monkeypatch.setattr(httpx, "get", get)


def test_gateway_down_shows_a_banner_instead_of_crashing(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> httpx.Response:
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(httpx, "get", refuse)
    at = _run()
    assert any("unreachable" in e.value for e in at.error)


def test_panels_show_posture_feed_and_totals(
    client: TestClient, stub: StubModel, fake_steps, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub.add(text("Paris."))
    client.post("/v1/chat/completions", headers=ANNA,
                json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "Capital?"}]})
    client.post("/v1/chat/completions", headers=ANNA,
                json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": INJECTION_PHRASE}]})
    _through(client, monkeypatch)
    at = _run()

    assert not at.error
    tiles = {m.label: m.value for m in at.metric}
    assert tiles["Profile"] == "strict"
    assert (tiles["Allowed"], tiles["Blocked"], tiles["Redacted"]) == ("1", "1", "0")
    posture, feed = _table(at, "source"), _table(at, "reason")
    assert "prompt_controls.injection.mode" in set(posture["control"])
    assert set(posture["source"]) <= {"explicit", "profile", "default"}
    assert list(feed["verdict"]) == ["block", "allow"]
    assert feed["reason"][0].startswith("The prompt matches a known injection phrase")
    assert [b.label for b in at.get("download_button")] == ["Download audit log (CSV)"]


def test_missing_policy_endpoint_shows_pending(
    client: TestClient, fake_steps, monkeypatch: pytest.MonkeyPatch
) -> None:
    _through(client, monkeypatch, missing=("/policy/effective",))
    at = _run()
    assert any("pending" in i.value for i in at.info)
    assert not at.error


def test_export_downloads_the_gateway_csv(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _through(client, monkeypatch)
    assert dashboard.export_csv().decode("utf-8").startswith("request_id,timestamp,verdict")


def test_export_when_the_gateway_is_down_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "get", lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("refused")))
    assert b"could not be reached" in dashboard.export_csv()


def test_refresh_interval_comes_from_the_policy() -> None:
    assert dashboard.refresh_seconds({"controls": {"dashboard.refresh_seconds": {"value": 5}}}) == 5
    assert dashboard.refresh_seconds(None) == dashboard.DEFAULT_REFRESH_S
    assert dashboard.refresh_seconds({"controls": {"dashboard.refresh_seconds": {"value": 0}}}) == 2


def test_disabled_control_is_shown_as_off() -> None:
    rows = dashboard.control_rows({
        "controls": {"prompt_controls.injection.mode": {"value": "off", "source": "explicit"},
                     "prompt_controls.semantic.enabled": {"value": True, "source": "profile"}},
        "disabled_controls": ["prompt_controls.injection"]})
    assert rows[0] == {"control": "prompt_controls.injection.mode", "mode": "off", "source": "explicit"}


def test_dashboard_never_opens_a_database_or_file() -> None:
    tree = ast.parse(Path(APP).read_text(encoding="utf-8"))
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not imported & {"sqlite3", "gateway", "db", "pathlib"}
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert "open" not in names
    source = Path(APP).read_text(encoding="utf-8")
    assert "demo.db" not in source.replace("never opens demo.db", "")


# ---------------------------------------------------------------------------
# Section 12: the seven panels
# ---------------------------------------------------------------------------

PANELS = ["Totals (today, UTC)", "Posture", "Live feed", "Threats", "Data access (today)",
          "Consumption (today, UTC)", "Performance (today)", "Export"]


def test_all_seven_panels_render_after_a_scripted_mix(
    scripted_mix: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _through(scripted_mix, monkeypatch)
    at = _run()

    assert not at.error
    assert [h.value for h in at.subheader] == PANELS
    tiles = {m.label: m.value for m in at.metric}
    assert (tiles["Allowed"], tiles["Blocked"]) == ("4", "3")
    assert tiles["Signature feed"] == "2026-10-03.1"
    assert tiles["Model digests"] == "2 ok"

    bindings = _table(at, "resolved")
    assert list(zip(bindings["role"], bindings["table"], bindings["resolved"], bindings["denied"])) == [
        ("intern", "salaries", 1, 1), ("sales_lead", "employees", 1, 0)]
    latency = _table(at, "p95 ms")
    assert list(latency["step"])[-1] == "total" and "authenticate" in set(latency["step"])
    assert (latency["median ms"] <= latency["p95 ms"]).all()

    bars = [p.proto.text for p in at.get("progress")]
    assert len(bars) == 4  # tokens and cost for anna and marek
    assert any(t.endswith("/ 20,000 tokens") for t in bars)


def test_posture_shows_a_rejected_reload_and_blocked_models(monkeypatch: pytest.MonkeyPatch) -> None:
    effective = {"version": "abc", "profile": "strict", "disabled_controls": [],
                 "controls": {"prompt_controls.injection.mode": {"value": "block", "source": "explicit"}}}
    health = {"policy": {"error": "Invalid policy: profile: expected one of strict, balanced, relaxed."},
              "feed": {"version": "2026-10-03.1", "error": None},
              "digests": {"checked": True, "ok": False, "models": {
                  "qwen2.5:3b": {"status": "mismatch"}, "qwen2.5:1.5b": {"status": "ok"}}}}
    bodies = {"/policy/effective": effective, "/health": health, "/metrics": {}}

    def get(url: str, params: Any = None, timeout: float = 0) -> httpx.Response:
        return httpx.Response(200, json=bodies[url.removeprefix(dashboard.GATEWAY_URL)])

    monkeypatch.setattr(httpx, "get", get)
    at = _run()
    errors = [e.value for e in at.error]
    assert any(e.startswith("Policy reload rejected") and "expected one of" in e for e in errors)
    assert any("qwen2.5:3b" in e for e in errors)
    assert {m.label: m.value for m in at.metric}["Model digests"] == "1 blocked"


def test_disabled_control_is_off_and_red_in_posture(client: TestClient, policy: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy.write_text(policy.read_text(encoding="utf-8").replace(
        "  injection:        { mode: block }", "  injection:        { mode: off }"), encoding="utf-8")
    client.post("/policy/reload")
    _through(client, monkeypatch)
    at = _run()
    posture = _table(at, "source")
    assert posture.loc[posture["control"] == "prompt_controls.injection.mode", "mode"].item() == "off"
    assert any("Disabled controls: prompt_controls.injection" in e.value for e in at.error)
    assert dashboard.ACCENT in dashboard._red_off("off") and dashboard._red_off("block") == ""


def test_posture_status_without_health_is_unknown() -> None:
    assert dashboard.posture_status(None) == {"feed": "unknown", "digests": "unknown", "digests_ok": None,
                                              "blocked_models": [], "errors": []}
    assert dashboard.posture_status({"digests": {"checked": True, "models": {"m": {"status": "unpinned"}}}})[
        "digests"] == "1 ok"


def test_budget_rows_cap_the_bar_and_survive_missing_limits() -> None:
    rows = dashboard.budget_rows({"tokens_and_cost_by_user": {"users": {
        "anna": {"role": "intern", "tokens": 30_000, "cost_usd": 0.1,
                 "limits": {"tokens_per_day": 20_000, "cost_per_day_usd": 0.5}},
        "ghost": {"role": "removed", "tokens": 5, "cost_usd": 0.0, "limits": {}},
    }}})
    assert rows[0]["token_share"] == 1.0 and rows[0]["cost_share"] == pytest.approx(0.2)
    assert rows[1]["token_limit"] is None and rows[1]["token_share"] == 0.0


def test_panel_rows_from_metrics() -> None:
    m = {"blocks_over_time": [{"minute": "2026-10-03T11:59:00+00:00", "requests": 2, "blocks": 1}],
         "tool_decisions_by_tool": {"send_email": {"allow": 2, "deny": 1}},
         "latency_by_step": {"authenticate": {"median_ms": 0.1, "p95_ms": 0.4, "count": 3}}}
    assert dashboard.over_time_rows(m) == [{"minute": "11:59", "requests": 2, "blocks": 1}]
    assert dashboard.tool_rows(m) == [{"tool": "send_email", "allowed": 2, "denied": 1}]
    assert dashboard.latency_rows(m) == [{"step": "authenticate", "median ms": 0.1, "p95 ms": 0.4, "requests": 3}]
    assert dashboard.count_rows({"b": 1, "a": 3, "c": 1}, "user") == [
        {"user": "a", "blocks": 3}, {"user": "b", "blocks": 1}, {"user": "c", "blocks": 1}]
    assert dashboard.binding_rows({}) == [] and dashboard.count_rows(None, "user") == []


def test_dashboard_works_against_t1_metrics_without_the_new_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """An older gateway without the section 12 keys still renders every panel."""
    t1 = {"requests_by_verdict": {"allow": 1, "block": 0, "redact": 0, "log": 0}, "blocks_by_control": {},
          "tokens_and_cost_by_user": {"day": "2026-10-03", "users": {}}, "last_requests": []}
    bodies = {"/policy/effective": {"version": "v", "profile": "strict", "controls": {}}, "/metrics": t1}

    def get(url: str, params: Any = None, timeout: float = 0) -> httpx.Response:
        path = url.removeprefix(dashboard.GATEWAY_URL)
        return httpx.Response(200, json=bodies[path]) if path in bodies else httpx.Response(404)

    monkeypatch.setattr(httpx, "get", get)
    at = _run()
    assert [h.value for h in at.subheader] == PANELS


def test_no_panel_is_taller_than_one_screen() -> None:
    tree = ast.parse(Path(APP).read_text(encoding="utf-8"))
    heights = [kw.value for n in ast.walk(tree) if isinstance(n, ast.Call) for kw in n.keywords if kw.arg == "height"]
    assert heights
    # The chart helpers forward their last argument as the height
    helpers = {"_minute_chart", "rank_chart", "tools_chart", "latency_chart", "timeline_chart"}
    heights += [n.args[-1] for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in helpers]
    for h in heights:
        if isinstance(h, ast.Dict) and [k.value for k in h.keys if isinstance(k, ast.Constant)] == ["band"]:
            continue  # bar thickness as a share of the row (Vega-Lite), not a pixel height
        if isinstance(h, ast.Constant):
            assert h.value <= dashboard.PANEL_HEIGHT
        elif isinstance(h, ast.Name) and h.id == "height":
            continue  # the forwarded parameter, checked at the call sites above
        else:  # PANEL_HEIGHT itself or min(PANEL_HEIGHT, ...)
            assert "PANEL_HEIGHT" in ast.unparse(h)
    assert dashboard.PANEL_HEIGHT <= 400


# ---------------------------------------------------------------------------
# Smooth refresh: /health never blocks a tick; charts build from metrics
# ---------------------------------------------------------------------------


def test_stale_health_is_served_at_once_while_a_thread_fetches_the_next(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    release, calls = threading.Event(), []

    def slow_fetch(path: str, timeout: float = 0) -> tuple[Any, str | None]:
        calls.append(path)
        if len(calls) > 1:
            release.wait(5)
        return {"n": len(calls)}, None

    monkeypatch.setattr(dashboard, "fetch", slow_fetch)
    cache = dashboard.HealthCache()
    assert cache.get(now=0.0) == ({"n": 1}, None)  # the first fetch waits: nothing to show yet
    stale = cache.fetched_at + dashboard.HEALTH_TTL_S + 1
    assert cache.get(now=stale) == ({"n": 1}, None)  # returns at once, refresh runs behind
    assert cache.get(now=stale) == ({"n": 1}, None)  # one refresh at a time
    release.set()
    for _ in range(100):
        if not cache.busy:
            break
        threading.Event().wait(0.02)
    assert cache.value == ({"n": 2}, None) and calls == ["/health", "/health"]


def test_charts_build_from_metrics_and_skip_empty_timelines() -> None:
    m = {"blocks_over_time": [{"minute": "2026-10-03T11:58:00+00:00", "requests": 3, "blocks": 0},
                              {"minute": "2026-10-03T11:59:00+00:00", "requests": 2, "blocks": 1}],
         "tool_decisions_by_tool": {"send_email": {"allow": 2, "deny": 1}},
         "latency_by_step": {"authenticate": {"median_ms": 0.1, "p95_ms": 0.4, "count": 3},
                             "total": {"median_ms": 9.0, "p95_ms": 20.0, "count": 3}}}
    assert dashboard.timeline_chart({}, "blocks", dashboard.ACCENT, 200) is None
    for chart in (dashboard.timeline_chart(m, "blocks", dashboard.ACCENT, 200),
                  dashboard.rank_chart(dashboard.count_rows({"injection": 2}, "control"), "control", "#000000", 200),
                  dashboard.tools_chart(dashboard.tool_rows(m), 200),
                  dashboard.latency_chart(dashboard.latency_rows(m), 200)):
        spec = chart.to_dict()
        assert 0 < spec["height"] <= 200
