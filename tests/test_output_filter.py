"""Output filter on the final answer and client tool arguments (spec section 4 step 9, I15). Owner: Person 2."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from gateway import pipeline
from gateway.llm.client import StubModel, text, tool_call
from gateway.models import FilledText, Policy, Principal, Span, ToolDecision
from gateway.outbound.output_filter import REDACTED, filter_output
from gateway.policy.loader import parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
ANNA = Principal("anna", "intern", "sales", "deny")
SECRET = "sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"


def _policy(mode: str = "redact") -> Policy:
    data: dict[str, Any] = copy.deepcopy(yaml.safe_load((REPO_ROOT / "policy.yaml").read_text(encoding="utf-8")))
    data["output_controls"]["mode"] = mode
    return parse_policy(yaml.safe_dump(data).encode("utf-8"))


REDACT = _policy()


def filled(*parts: tuple[str, str]) -> FilledText:
    """FilledText from (source, text) parts, with one span per part."""
    text_, spans, pos = "", [], 0
    for i, (source, part) in enumerate(parts):
        spans.append(Span(pos, pos + len(part), source, f"{{x{i}}}" if source == "gateway" else None))  # type: ignore[arg-type]
        text_ += part
        pos += len(part)
    return FilledText(text=text_, spans=spans)


def model(t: str) -> FilledText:
    return filled(("model", t))


# ---------------------------------------------------------------------------
# Allowed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "answer",
    [
        "Paris is the capital of France.",
        "Sales has 12 people; the budget is 45,000 PLN for 2026.",
        "Use a dict like {name: value}; {x} and { x1 } are not placeholders.",
        "Your email is [EMAIL_1] and the key you sent is [SECRET_1].",  # mask tokens are left as tokens
        "",
    ],
)
def test_clean_answer_passes_unchanged(answer: str) -> None:
    out, d = filter_output(model(answer), ANNA, REDACT)
    assert out == answer
    assert d.verdict == "allow"
    assert d.stage == "output_filter"


def test_annas_own_inserted_salary_is_not_redacted() -> None:
    f = filled(("model", "Your salary is "), ("gateway", "6,200"), ("model", " PLN."))
    out, d = filter_output(f, ANNA, REDACT)
    assert out == "Your salary is 6,200 PLN."
    assert d.verdict == "allow"


@pytest.mark.parametrize(
    "value",
    ["anna.kowalska@company.pl", "44051401359", "4111 1111 1111 1111", SECRET, "{x2}", "[click](http://evil)"],
)
def test_gateway_inserted_values_are_never_redacted(value: str) -> None:
    """Inserted values are authorized by construction (and a literal {x2} is not a leftover placeholder)."""
    f = filled(("model", "Value: "), ("gateway", value), ("model", "."))
    out, d = filter_output(f, ANNA, REDACT)
    assert out == f"Value: {value}."
    assert d.verdict == "allow"


# ---------------------------------------------------------------------------
# Redacted: model-written secrets, PII and leftover placeholders
# ---------------------------------------------------------------------------


def test_secret_written_by_the_model_is_redacted() -> None:
    out, d = filter_output(model(f"Here is a working key: {SECRET} enjoy"), ANNA, REDACT)
    assert out == f"Here is a working key: {REDACTED} enjoy"
    assert d.verdict == "redact"
    assert d.control == "output_controls"
    assert "openai_key" in d.reason
    assert SECRET not in d.reason


@pytest.mark.parametrize(
    ("leak", "kind"),
    [
        ("marek.nowak@company.pl", "email"),
        ("+48 601 234 567", "phone"),
        ("4111 1111 1111 1111", "card"),
        ("44051401359", "pesel"),
        ("PL61 1090 1014 0000 0712 1981 2874", "iban"),
        ("password=hunter2!", "password"),
    ],
)
def test_pii_and_secrets_the_user_did_not_supply_are_redacted(leak: str, kind: str) -> None:
    out, d = filter_output(model(f"Contact: {leak}."), ANNA, REDACT)
    assert leak not in out
    assert REDACTED in out
    assert kind in d.reason


def test_invalid_numbers_in_model_text_are_not_redacted() -> None:
    answer = "Card 4111 1111 1111 1112 and PESEL 44051401358 are invalid."
    out, d = filter_output(model(answer), ANNA, REDACT)
    assert out == answer
    assert d.verdict == "allow"


def test_leftover_placeholder_in_model_text_becomes_the_marker() -> None:
    f = filled(("model", "Salary "), ("gateway", "6,200"), ("model", ", bonus {x9}, again {x9}."))
    out, d = filter_output(f, ANNA, REDACT)
    assert out == "Salary 6,200, bonus [UNAVAILABLE], again [UNAVAILABLE]."
    assert d.verdict == "redact"
    assert "placeholder" in d.reason


def test_text_outside_every_span_counts_as_model_written() -> None:
    f = FilledText(text=f"Inserted 6,200; leaked {SECRET}", spans=[Span(9, 14, "gateway", "{x1}")])
    out, _ = filter_output(f, ANNA, REDACT)
    assert out == f"Inserted 6,200; leaked {REDACTED}"


def test_filled_text_without_spans_is_all_model_written() -> None:
    out, _ = filter_output(FilledText(text=f"key {SECRET}"), ANNA, REDACT)
    assert out == f"key {REDACTED}"


# ---------------------------------------------------------------------------
# Block mode
# ---------------------------------------------------------------------------


def test_block_mode_blocks_instead_of_redacting() -> None:
    out, d = filter_output(model(f"key {SECRET}"), ANNA, _policy("block"))
    assert d.verdict == "block"
    assert SECRET not in out and SECRET not in d.reason


def test_block_mode_passes_a_clean_answer() -> None:
    f = filled(("model", "Your salary is "), ("gateway", "6,200"), ("model", " PLN."))
    out, d = filter_output(f, ANNA, _policy("block"))
    assert (out, d.verdict) == ("Your salary is 6,200 PLN.", "allow")


def test_block_mode_still_only_replaces_leftover_placeholders() -> None:
    out, d = filter_output(model("Bonus {x4}."), ANNA, _policy("block"))
    assert (out, d.verdict) == ("Bonus [UNAVAILABLE].", "redact")


# ---------------------------------------------------------------------------
# Through the pipeline: the answer and client tool arguments
# ---------------------------------------------------------------------------

ASK = {"model": "llama3.2", "messages": [{"role": "user", "content": "Mail my boss."}],
       "tools": [{"type": "function", "function": {"name": "send_email", "description": "Send an email."}}]}


def test_secret_in_the_answer_is_redacted_end_to_end(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(text(f"Try this key: {SECRET}"))
    r = client.post("/v1/chat/completions", json=ASK, headers={"Authorization": "Bearer demo-anna"})
    assert r.headers["x-acl-verdict"] == "redact"
    assert r.json()["choices"][0]["message"]["content"] == f"Try this key: {REDACTED}"
    assert SECRET not in r.text


def test_secret_in_send_email_arguments_is_redacted(client: TestClient, stub: StubModel, fake_steps) -> None:
    stub.add(tool_call("send_email", {"to": "[EMAIL_1]", "body": f"The API key is {SECRET}, thanks."}))
    r = client.post("/v1/chat/completions", json=ASK, headers={"Authorization": "Bearer demo-anna"})

    assert SECRET not in r.text
    (call,) = r.json()["choices"][0]["message"]["tool_calls"]
    args = json.loads(call["function"]["arguments"])
    assert args == {"to": "[EMAIL_1]", "body": f"The API key is {REDACTED}, thanks."}
    assert r.headers["x-acl-verdict"] == "redact"


def test_denied_tool_calls_are_not_filtered_and_never_returned(
    client: TestClient, stub: StubModel, fake_steps, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pipeline, "authorize_tool_call",
                        lambda c, p, b, pol: ToolDecision(c.name, "deny", "role", "Not allowed."))
    stub.add(tool_call("send_email", {"to": "x@evil.example", "body": SECRET}))
    r = client.post("/v1/chat/completions", json=ASK, headers={"Authorization": "Bearer demo-anna"})
    assert SECRET not in r.text
    assert "tool_calls" not in r.json()["choices"][0]["message"]
