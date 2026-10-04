"""Demo agent: a plain OpenAI-SDK client of the gateway. Spec section 4 'Worked examples' (C, D), section 13.

Owner: Person 4. The agent is untrusted by design: it has no security logic, so these
tests check client behaviour only (history, tool round trip, showing the verdict).
The agent's real OpenAI client talks to the in-process gateway through TestClient.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from demo_agent import app as agent
from gateway.llm.client import StubModel, text, tool_call
from tests.conftest import INJECTION_PHRASE

REPO_ROOT = Path(__file__).resolve().parent.parent


def _client(client: TestClient, user: str = "anna"):
    return agent.make_client(agent.USERS[user], http_client=client)


def test_users_map_to_the_demo_keys() -> None:
    assert agent.USERS == {"anna": "demo-anna", "marek": "demo-marek", "piotr": "demo-piotr"}


def test_base_url_is_the_gateway() -> None:
    assert str(agent.make_client("demo-anna").base_url).rstrip("/") == "http://localhost:8000/v1"
    assert 'base_url="http://localhost:8000/v1"' in (REPO_ROOT / "demo_agent" / "app.py").read_text(encoding="utf-8")


def test_answer_shows_the_verdict_and_history_is_resent(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(text("Paris."), text("About 2 million."))
    history: list[dict] = []
    turn = agent.chat_turn(_client(client), history, "Capital of France?")
    assert (turn.answer, turn.verdict, turn.reason, turn.error) == ("Paris.", "allow", None, None)
    assert history == [{"role": "user", "content": "Capital of France?"}, {"role": "assistant", "content": "Paris."}]

    agent.chat_turn(_client(client), history, "How many people live there?")
    sent = [m for m in stub.calls[1].messages if m["role"] in ("user", "assistant")]
    assert [m["content"] for m in sent] == ["Capital of France?", "Paris.", "How many people live there?"]
    assert len(history) == 4


def test_client_tool_runs_locally_and_its_result_goes_back(
    client: TestClient, stub: StubModel, fake_steps, capsys: pytest.CaptureFixture[str]
) -> None:
    stub.add(tool_call("create_ticket", {"title": "Printer", "body": "Jammed"}), text("Ticket created."))
    history: list[dict] = []
    turn = agent.chat_turn(_client(client, "piotr"), history, "Open a ticket about the printer")

    assert turn.answer == "Ticket created." and turn.verdict == "allow"
    assert turn.actions == ["create_ticket: would create ticket 'Printer' (Jammed)"]
    assert "would create ticket 'Printer'" in capsys.readouterr().out
    assert [m["role"] for m in history] == ["user", "assistant", "tool", "assistant"]
    call = history[1]["tool_calls"][0]
    assert history[2]["tool_call_id"] == call["id"]
    tool_msgs = [m for m in stub.calls[1].messages if m["role"] == "tool"]
    assert [m["content"] for m in tool_msgs] == ["Ticket created: Printer"]


def test_blocked_tool_call_shows_the_block_and_runs_nothing(
    client: TestClient, stub: StubModel, fake_steps, capsys: pytest.CaptureFixture[str]
) -> None:
    stub.add(tool_call("send_email", {"to": "boss@gmail.com", "subject": "Hi", "body": "x"}))
    turn = agent.chat_turn(_client(client), [], "Email my boss")
    assert turn.verdict == "block"
    assert turn.reason == "The action send_email was blocked by policy."
    assert turn.actions == []
    assert "would send" not in capsys.readouterr().out


def test_blocked_request_shows_the_gateway_reason(client: TestClient, stub: StubModel, fake_steps) -> None:
    history: list[dict] = []
    turn = agent.chat_turn(_client(client), history, INJECTION_PHRASE)
    assert turn.verdict == "block"
    assert turn.reason and turn.reason.startswith("The prompt matches a known injection phrase")
    assert stub.calls == []
    assert history[-1]["role"] == "assistant"  # a real agent keeps the refusal in its history


def test_auth_failure_is_shown_not_raised(client: TestClient, stub: StubModel, fake_steps) -> None:
    history: list[dict] = []
    turn = agent.chat_turn(agent.make_client("wrong-key", http_client=client), history, "Hi")
    assert turn.error is not None and "401" in turn.error
    assert history == []  # the failed turn is not kept


def test_tool_rounds_are_bounded(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.fallback = tool_call("create_ticket", {"title": "again", "body": "b"})
    turn = agent.chat_turn(_client(client, "piotr"), [], "Loop forever")
    assert len(turn.actions) == agent.MAX_TOOL_ROUNDS
    assert turn.error is not None and "rounds" in turn.error


def test_tool_fakes_handle_bad_arguments() -> None:
    assert agent.run_tool("send_email", json.dumps({"to": "a@company.pl", "subject": "S", "body": "B"})) == (
        "Email to a@company.pl queued: S")
    assert agent.run_tool("send_email", "{not json").startswith("Error")
    assert agent.run_tool("delete_everything", "{}").startswith("Error")


def test_agent_has_no_security_logic() -> None:
    tree = ast.parse((REPO_ROOT / "demo_agent" / "app.py").read_text(encoding="utf-8"))
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert "gateway" not in imported and "sqlite3" not in imported


def test_page_renders_and_survives_a_gateway_that_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    from streamlit.testing.v1 import AppTest

    import openai

    def refuse(*args: object, **kwargs: object) -> None:
        raise openai.APIConnectionError(request=httpx.Request("POST", "http://localhost:8000/v1/chat/completions"))

    monkeypatch.setattr(openai.resources.chat.completions.Completions, "create", refuse)
    at = AppTest.from_file(str(REPO_ROOT / "demo_agent" / "app.py"), default_timeout=20)
    at.run()
    assert not at.exception
    assert at.sidebar.selectbox[0].options == ["anna", "marek", "piotr"]
    at.chat_input[0].set_value("Hello").run()
    assert not at.exception
    assert any("unreachable" in e.value for e in at.error)


def test_empty_conversation_offers_the_worked_examples_and_sends_one(monkeypatch: pytest.MonkeyPatch) -> None:
    from streamlit.testing.v1 import AppTest

    import openai

    sent: list[Any] = []

    def refuse(self: object, **kwargs: Any) -> None:
        sent.append(kwargs["messages"][-1]["content"])
        raise openai.APIConnectionError(request=httpx.Request("POST", "http://localhost:8000/v1/chat/completions"))

    monkeypatch.setattr(openai.resources.chat.completions.Completions, "create", refuse)
    at = AppTest.from_file(str(REPO_ROOT / "demo_agent" / "app.py"), default_timeout=20)
    at.run()
    buttons = {b.label: b for b in at.button}
    first = [agent.SCENARIO_BY_ID[i] for i in agent.FIRST_DEAL]
    assert {s.label for s in first} <= set(buttons)
    buttons[first[0].label].click().run()
    assert not at.exception
    assert sent == [first[0].prompt]
    assert any("unreachable" in e.value for e in at.error)
    scenario_labels = {s.label for s in agent.SCENARIOS}
    shown = [b.label for b in at.button if b.label in scenario_labels]
    assert first[0].label not in shown and len(shown) == agent.DECK_SIZE  # replaced, not repeated


# ---------------------------------------------------------------------------
# Scenario buttons: a pool of edge cases dealt four at a time, never repeated
# ---------------------------------------------------------------------------


def test_a_new_conversation_starts_with_the_worked_examples() -> None:
    deck = agent.Deck()
    assert deck.visible == list(agent.FIRST_DEAL) and not deck.used
    assert len(agent.FIRST_DEAL) == agent.DECK_SIZE
    assert all(i in agent.SCENARIO_BY_ID for i in agent.FIRST_DEAL)


def test_a_used_scenario_is_replaced_in_place_by_an_unused_one() -> None:
    import random

    deck = agent.Deck()
    agent.use_scenario(deck, "email_out", random.Random(1))
    assert len(deck.visible) == agent.DECK_SIZE and "email_out" not in deck.visible
    assert deck.visible[:2] == ["hidden", "mixed"] and deck.visible[3] == "inject_en"  # same slot
    assert deck.visible[2] not in agent.FIRST_DEAL


def test_scenarios_never_repeat_and_run_out_cleanly() -> None:
    import random

    rng, deck, seen = random.Random(7), agent.Deck(), []
    while deck.visible:
        assert len(set(deck.visible)) == len(deck.visible)  # no duplicates on screen
        assert not set(deck.visible) & deck.used  # nothing used comes back
        seen.append(deck.visible[0])
        agent.use_scenario(deck, deck.visible[0], rng)
    assert sorted(seen) == sorted(s.id for s in agent.SCENARIOS)


def test_typing_a_scenario_prompt_by_hand_uses_it_up() -> None:
    import random

    deck = agent.Deck()
    assert agent.scenario_for_prompt("  " + agent.SCENARIO_BY_ID["hidden"].prompt + " ") == "hidden"
    assert agent.scenario_for_prompt("What is the weather?") is None
    agent.use_scenario(deck, "secret", random.Random(0))  # not on screen: only marked used
    assert "secret" in deck.used and deck.visible == list(agent.FIRST_DEAL)


def test_every_scenario_is_unique_and_explained() -> None:
    ids = [s.id for s in agent.SCENARIOS]
    assert len(ids) == len(set(ids)) and len({s.prompt for s in agent.SCENARIOS}) == len(ids)
    assert all(s.label and s.prompt and s.shows for s in agent.SCENARIOS)
