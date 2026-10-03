"""Real Ollama through the OpenAI-compatible client. Skipped when Ollama is down. Owner: Person 1."""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from gateway.llm.client import call_model, get_client
from gateway.llm.prompts import QUERY_DATA_TOOL, build_system_message, load_schema
from gateway.policy.loader import load_policy, setting

pytestmark = pytest.mark.live

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def policy():
    p = load_policy(REPO_ROOT / "policy.yaml")
    name = setting(p, "models.answer.name")
    with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=2) as r:  # noqa: S310 - fixed local URL
        pulled = {m["name"] for m in json.load(r)["models"]}
    if name not in pulled and f"{name}:latest" not in pulled:
        pytest.skip(f"Ollama model {name} is not pulled")
    return p


def test_ollama_answers_a_plain_question(policy) -> None:
    reply = call_model(
        get_client("answer", policy), "answer", policy,
        [{"role": "user", "content": "Reply with one word: what colour is the sky on a clear day?"}],
    )
    assert reply.content and reply.content.strip()
    assert reply.completion_tokens > 0


def test_ollama_is_offered_query_data(policy) -> None:
    messages = [
        {"role": "system", "content": build_system_message(load_schema())},
        {"role": "user", "content": "How many products are in the catalogue?"},
    ]
    reply = call_model(get_client("answer", policy), "answer", policy, messages, tools=[QUERY_DATA_TOOL])

    # A small model may answer in text instead; either way the reply must be well formed.
    assert reply.content or reply.tool_calls
    for call in reply.tool_calls:
        assert call.name == "query_data"
        args = json.loads(call.arguments)
        assert isinstance(args.get("sql"), str) and args["sql"].strip()
