"""One Streamlit app for the public demo: the agent and the dashboard as two pages on one port."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import openai
import pytest
from streamlit.testing.v1 import AppTest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def gateway_down(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse_get(*args: Any, **kwargs: Any) -> httpx.Response:
        raise httpx.ConnectError("refused")

    def refuse_chat(*args: Any, **kwargs: Any) -> None:
        raise openai.APIConnectionError(request=httpx.Request("POST", "http://localhost:8000/v1/chat/completions"))

    monkeypatch.setattr(httpx, "get", refuse_get)
    monkeypatch.setattr(openai.resources.chat.completions.Completions, "create", refuse_chat)


def test_the_agent_is_the_landing_page_and_the_dashboard_is_one_switch_away(gateway_down: None) -> None:
    at = AppTest.from_file(str(REPO_ROOT / "app.py"), default_timeout=30)
    at.run()
    assert not at.exception, at.exception
    assert at.sidebar.selectbox[0].options == ["anna", "marek", "piotr"]
    at.chat_input[0].set_value("Hello").run()
    assert any("unreachable" in e.value for e in at.error)

    at.session_state["histories"]["anna"] += [{"role": "user", "content": "Hello"},
                                              {"role": "assistant", "content": "Hi, Anna."}]

    at.switch_page("dashboard/app.py").run()
    assert not at.exception, at.exception
    assert any("Gateway unreachable" in e.value for e in at.error)
    assert not at.chat_input  # the agent's page is gone

    at.switch_page("demo_agent/app.py").run()
    assert not at.exception, at.exception
    assert [m.markdown[0].value for m in at.chat_message] == ["Hello", "Hi, Anna."]  # history kept
