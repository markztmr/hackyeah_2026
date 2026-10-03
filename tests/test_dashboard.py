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
from streamlit.testing.v1 import AppTest

from dashboard import app as dashboard
from gateway.llm.client import StubModel, text
from tests.conftest import INJECTION_PHRASE

REPO_ROOT = Path(__file__).resolve().parent.parent
APP = str(REPO_ROOT / "dashboard" / "app.py")
ANNA = {"Authorization": "Bearer demo-anna"}


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
    posture, feed = (df.value for df in at.dataframe)
    assert "prompt_controls.injection.mode" in set(posture["control"])
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
