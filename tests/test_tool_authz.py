"""Client tool authorization: role tool list, argument rules, placeholder egress.

Spec section 4 step 7, section 5 'Client tool authorization' and 'Egress rule', I11.
Owner: Person 3.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway.agency import loop as loop_module
from gateway.agency.tool_authz import authorize_tool_call
from gateway.llm.client import StubModel, text, tool_call
from gateway.models import Binding, Policy, Principal, ToolCall
from tests.test_authorizer import ANNA, MAREK, PIOTR, STRICT, _data, _parse


def _call(name: str, args: dict[str, Any] | str) -> ToolCall:
    return ToolCall(id="c1", name=name, arguments=args)  # type: ignore[arg-type]


def _b(name: str, label: str | None, status: str = "resolved", value: Any = 25) -> Binding:
    return Binding(name=name, sql="SELECT 1", purpose="t", expect="scalar",  # type: ignore[arg-type]
                   status=status, value=value, label=label)  # type: ignore[arg-type]


HEADCOUNT = _b("{x1}", "internal", value=25)
SALARY = _b("{x2}", "sensitive", value=16500)
BINDINGS = {b.name: b for b in (HEADCOUNT, SALARY)}


def _decide(name: str, args: dict[str, Any] | str, who: Principal = PIOTR,
            bindings: dict[str, Binding] | None = None, policy: Policy = STRICT) -> Any:
    return authorize_tool_call(_call(name, args), who, BINDINGS if bindings is None else bindings, policy)


def _allowed(name: str, args: dict[str, Any] | str, **kw: Any) -> bool:
    return _decide(name, args, **kw).verdict == "allow"


# ---------------------------------------------------------------------------
# Role tool list
# ---------------------------------------------------------------------------


def test_piotr_create_ticket_passes() -> None:
    d = _decide("create_ticket", {"title": "Printer broken"})
    assert d.verdict == "allow" and d.tool == "create_ticket"


def test_anna_transfer_funds_is_denied() -> None:
    d = _decide("transfer_funds", {"amount": 100}, ANNA)
    assert d.verdict == "deny" and d.rule == "not_listed"
    assert d.reason


def test_tool_listed_for_another_role_only_is_denied() -> None:
    assert not _allowed("create_ticket", {"title": "x"}, who=ANNA)
    assert _allowed("create_ticket", {"title": "x"}, who=MAREK)


@pytest.mark.parametrize("name", ["Create_Ticket", "create_ticket ", "create-ticket", "сreate_ticket", "query_data"])
def test_name_must_match_a_listed_tool_exactly(name: str) -> None:
    assert not _allowed(name, {"title": "x"})


def test_unknown_role_is_denied() -> None:
    ghost = Principal("piotr", "ghost", "hr", "allow")
    assert not _allowed("create_ticket", {"title": "x"}, who=ghost)


def test_unsafe_tool_name_is_not_echoed_in_the_decision() -> None:
    d = _decide("sk_live_abcdefghijklmnop1234", {})
    assert d.verdict == "deny"
    assert "sk_live" not in d.tool and "sk_live" not in d.reason


# ---------------------------------------------------------------------------
# Argument rules
# ---------------------------------------------------------------------------


def test_send_email_inside_the_company_passes() -> None:
    assert _allowed("send_email", {"to": "anna.zielinska@company.pl", "body": "hi"}, who=ANNA)


@pytest.mark.parametrize("to", [
    "someone@gmail.com",
    "anna@company.pl\n",                  # $ would match before a trailing newline
    "anna@company.pl.evil.com",
    "anna@cоmpany.pl",                    # Cyrillic o
    "anna@company.pl, x@gmail.com",
    "",
])
def test_send_email_outside_the_company_is_denied(to: str) -> None:
    d = _decide("send_email", {"to": to, "body": "hi"}, ANNA)
    assert d.verdict == "deny" and d.rule == "allow_pattern"
    assert "gmail" not in d.reason


@pytest.mark.parametrize("args", [
    {"body": "hi"},                                       # rule argument missing
    {"to": ["a@company.pl"], "body": "hi"},               # not a string
    {"to": 5},
    {"To": "x@gmail.com", "body": "hi"},                  # case variant of a ruled argument
    {"to": "a@company.pl", "TO": "x@gmail.com"},
    {"to": "a@company.pl", "t_o": "x@gmail.com"},
])
def test_allow_pattern_fails_closed(args: dict[str, Any]) -> None:
    assert not _allowed("send_email", args, who=ANNA)


def _rules_policy() -> Policy:
    data = _data()
    data["roles"]["hr_manager"]["tools"]["create_ticket"] = {
        "args": {"title": {"deny_pattern": r"\.\./"}, "amount": {"max": 500}},
    }
    return _parse(data)


RULES = _rules_policy()


@pytest.mark.parametrize(("args", "ok"), [
    ({"title": "Printer broken", "amount": 500}, True),
    ({"title": "Printer broken", "amount": 499.5}, True),
    ({"title": "Printer broken"}, True),                   # optional numeric argument absent
    ({"title": "../../etc/passwd"}, False),
    ({"title": "a\\..\\b ../"}, False),
    ({"title": "x", "amount": 501}, False),
    ({"title": "x", "amount": "400"}, False),             # numbers only
    ({"title": "x", "amount": True}, False),
    ({"title": "x", "amount": float("inf")}, False),
    ({"title": "x", "amount": None}, False),
    ({"title": ["../"]}, False),                           # deny_pattern on a non-string fails closed
])
def test_deny_pattern_and_max(args: dict[str, Any], ok: bool) -> None:
    assert _allowed("create_ticket", args, policy=RULES) is ok


def test_nan_from_json_is_denied() -> None:
    args = json.loads('{"title": "x", "amount": NaN}')
    assert not _allowed("create_ticket", args, policy=RULES)


def test_loader_accepts_deny_pattern_and_max_and_rejects_bad_rules() -> None:
    from gateway.policy.loader import PolicyError

    assert RULES is not None
    data = _data()
    data["roles"]["hr_manager"]["tools"]["create_ticket"] = {"args": {"title": {"deny_pattern": "("}}}
    with pytest.raises(PolicyError):
        _parse(data)
    data["roles"]["hr_manager"]["tools"]["create_ticket"] = {"args": {"amount": {"max": "lots"}}}
    with pytest.raises(PolicyError):
        _parse(data)
    data["roles"]["hr_manager"]["tools"]["create_ticket"] = {"args": {"amount": {"maximum": 5}}}
    with pytest.raises(PolicyError):
        _parse(data)


@pytest.mark.parametrize("args", ["{not json", "[1, 2]", "", None])
def test_arguments_that_are_not_a_json_object_are_denied(args: Any) -> None:
    d = _decide("create_ticket", args)
    assert d.verdict == "deny" and d.rule == "malformed_arguments"


# ---------------------------------------------------------------------------
# Egress: placeholders in arguments
# ---------------------------------------------------------------------------


def test_piotr_may_email_an_internal_headcount() -> None:
    assert _allowed("send_email", {"to": "team@company.pl", "body": "Headcount: {x1}"})


def test_only_allow_pattern_matches_count_as_policy_approved() -> None:
    from gateway.agency.tool_authz import policy_approved_arguments

    call = _call("send_email", {"to": "team@company.pl", "body": "x@company.pl"})
    assert policy_approved_arguments(call, PIOTR, STRICT) == {"to"}
    assert policy_approved_arguments(_call("send_email", {"to": "x@gmail.com"}), PIOTR, STRICT) == set()
    assert policy_approved_arguments(_call("create_ticket", {"title": "t"}), PIOTR, STRICT) == set()


def test_pipeline_redacts_pii_in_unruled_arguments_but_not_the_approved_recipient(
        client: TestClient, stub: StubModel, fake_steps: Any) -> None:
    stub.add(tool_call("send_email", {"to": "team@company.pl", "body": "CEO email: katarzyna.nowak@company.pl"}))
    msg = _ask(client, "demo-piotr", [SEND_EMAIL])
    (call,) = msg["tool_calls"]
    args = json.loads(call["function"]["arguments"])
    assert args["to"] == "team@company.pl"
    assert "katarzyna.nowak" not in args["body"]


def test_piotr_may_not_email_a_salary() -> None:
    d = _decide("send_email", {"to": "team@company.pl", "body": "Salary: {x2}"})
    assert d.verdict == "deny" and d.rule == "egress"
    assert "16500" not in d.reason


def test_tool_without_max_label_may_not_carry_any_placeholder() -> None:
    assert not _allowed("create_ticket", {"title": "Headcount {x1}"})       # Piotr, no max_label
    assert not _allowed("send_email", {"to": "a@company.pl", "body": "{x1}"}, who=ANNA)


@pytest.mark.parametrize("status", ["denied", "rejected", "empty", "error"])
def test_non_resolved_placeholder_is_not_sent_as_a_marker(status: str) -> None:
    b = _b("{x1}", "internal", status=status, value=None)
    assert not _allowed("send_email", {"to": "a@company.pl", "body": "{x1}"}, bindings={"{x1}": b})


def test_unknown_placeholder_denies() -> None:
    assert not _allowed("send_email", {"to": "a@company.pl", "body": "{x9}"})


def test_binding_without_label_denies() -> None:
    assert not _allowed("send_email", {"to": "a@company.pl", "body": "{x1}"},
                        bindings={"{x1}": _b("{x1}", None)})


@pytest.mark.parametrize("args", [
    {"to": "a@company.pl", "body": {"lines": ["ok", "Salary {x2}"]}},
    {"to": "a@company.pl", "body": "ok", "{x2}": "key"},
    {"to": "a@company.pl", "cc": ["{x2}"]},
])
def test_placeholders_are_found_anywhere_in_the_arguments(args: dict[str, Any]) -> None:
    assert not _allowed("send_email", args)


# ---------------------------------------------------------------------------
# Through the pipeline: denied calls removed, allowed ones filled
# ---------------------------------------------------------------------------

SEND_EMAIL = {"type": "function", "function": {"name": "send_email", "description": "Send an email."}}
CREATE_TICKET = {"type": "function", "function": {"name": "create_ticket", "description": "Open a ticket."}}
TRANSFER = {"type": "function", "function": {"name": "transfer_funds", "description": "Pay."}}


def _ask(client: TestClient, key: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
    r = client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {key}"},
                    json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "Do it."}], "tools": tools})
    assert r.status_code == 200
    return r.json()["choices"][0]["message"]


@pytest.fixture
def labelled(monkeypatch: pytest.MonkeyPatch) -> None:
    """query_data resolves headcount queries to 25 (internal) and salary queries to 16500 (sensitive)."""
    def execute(b: Binding, p: Any, policy: Any) -> Binding:
        b.status = "resolved"
        b.value, b.label = (16500, "sensitive") if "salar" in b.sql else (25, "internal")
        return b
    monkeypatch.setattr(loop_module, "execute", execute)


def test_pipeline_piotr_create_ticket_is_returned(client: TestClient, stub: StubModel, fake_steps: Any) -> None:
    stub.add(tool_call("create_ticket", {"title": "Printer broken"}))
    msg = _ask(client, "demo-piotr", [CREATE_TICKET])
    (call,) = msg["tool_calls"]
    assert call["function"]["name"] == "create_ticket"


def test_pipeline_anna_transfer_funds_is_removed(client: TestClient, stub: StubModel, fake_steps: Any,
                                                  audit_records: Any) -> None:
    stub.add(tool_call("transfer_funds", {"amount": 100}))
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer demo-anna"},
                    json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "Pay."}], "tools": [TRANSFER]})
    msg = r.json()["choices"][0]["message"]
    assert not msg.get("tool_calls")
    assert msg["content"] == "The action transfer_funds was blocked by policy."
    assert r.headers["x-acl-verdict"] == "block"
    (rec,) = audit_records()
    assert [(t["tool"], t["verdict"]) for t in rec["tool_decisions"]] == [("transfer_funds", "deny")]


def test_pipeline_send_email_to_gmail_is_removed(client: TestClient, stub: StubModel, fake_steps: Any) -> None:
    stub.add(tool_call("send_email", {"to": "boss@gmail.com", "body": "hi"}))
    msg = _ask(client, "demo-anna", [SEND_EMAIL])
    assert not msg.get("tool_calls")
    assert "send_email" in msg["content"]


def test_pipeline_piotr_send_email_with_headcount_is_filled(client: TestClient, stub: StubModel,
                                                            fake_steps: Any, labelled: None) -> None:
    stub.add(tool_call("query_data", {"sql": "SELECT count(*) FROM employees", "purpose": "t", "expect": "scalar"}),
             tool_call("send_email", {"to": "team@company.pl", "body": "Headcount: {x1}"}))
    msg = _ask(client, "demo-piotr", [SEND_EMAIL])
    (call,) = msg["tool_calls"]
    assert json.loads(call["function"]["arguments"]) == {"to": "team@company.pl", "body": "Headcount: 25"}


def test_pipeline_piotr_send_email_with_salary_is_removed(client: TestClient, stub: StubModel,
                                                          fake_steps: Any, labelled: None) -> None:
    stub.add(tool_call("query_data", {"sql": "SELECT salary FROM salaries", "purpose": "t", "expect": "scalar"}),
             tool_call("send_email", {"to": "team@company.pl", "body": "Salary: {x1}"}))
    msg = _ask(client, "demo-piotr", [SEND_EMAIL])
    assert not msg.get("tool_calls")
    assert "16500" not in json.dumps(msg)
    assert msg["content"] == "The action send_email was blocked by policy."


def test_pipeline_only_denied_calls_are_removed(client: TestClient, stub: StubModel, fake_steps: Any) -> None:
    stub.add(tool_call("create_ticket", {"title": "ok"}) + tool_call("transfer_funds", {"amount": 1}))
    msg = _ask(client, "demo-piotr", [CREATE_TICKET, TRANSFER])
    assert [c["function"]["name"] for c in msg["tool_calls"]] == ["create_ticket"]


def test_pipeline_names_every_blocked_tool(client: TestClient, stub: StubModel, fake_steps: Any) -> None:
    stub.add(tool_call("transfer_funds", {"amount": 1}) + tool_call("delete_employee", {"id": "anna"}))
    msg = _ask(client, "demo-piotr", [TRANSFER])
    assert msg["content"] == "The actions transfer_funds, delete_employee were blocked by policy."


def test_pipeline_malformed_arguments_are_denied_and_named(client: TestClient, stub: StubModel, fake_steps: Any,
                                                           audit_records: Any) -> None:
    stub.add(tool_call("create_ticket", "{not json"))
    msg = _ask(client, "demo-piotr", [CREATE_TICKET])
    assert not msg.get("tool_calls")
    assert msg["content"] == "The action create_ticket was blocked by policy."
    (rec,) = audit_records()
    assert [(t["tool"], t["rule"]) for t in rec["tool_decisions"]] == [("create_ticket", "malformed_arguments")]


# ---------------------------------------------------------------------------
# Red-team regressions (tests/test_redteam_tool_authz.py covers them end to end)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("args", [
    {"to": "{x1}@company.pl", "body": "hi"},     # allow_pattern would match before fill
    {"to": "team@company.pl", "body": "hi", "cc": "x"},
])
def test_a_ruled_argument_may_not_carry_a_placeholder(args: dict[str, Any]) -> None:
    ok = "{x1}" not in json.dumps(args)
    assert _allowed("send_email", args) is ok


def test_ruled_argument_with_placeholder_is_denied_even_under_deny_pattern() -> None:
    data = _data()
    data["roles"]["hr_manager"]["tools"]["create_ticket"] = {
        "args": {"title": {"deny_pattern": r"\.\./"}}, "max_label": "internal"}
    d = _decide("create_ticket", {"title": "{x1}"}, policy=_parse(data))
    assert d.verdict == "deny" and d.rule == "egress"


def test_placeholder_is_not_policy_approved() -> None:
    from gateway.agency.tool_authz import policy_approved_arguments

    assert policy_approved_arguments(_call("send_email", {"to": "{x1}@company.pl"}), PIOTR, STRICT) == set()


def _disclosed(value: Any, label: str = "internal") -> dict[str, Binding]:
    b = _b("{x1}", label, value=value)
    b.disclosed = True
    return {"{x1}": b}


@pytest.mark.parametrize("args", [
    {"to": "a@company.pl", "body": "Target is Q3-target-91827."},
    {"to": "a@company.pl", "body": "target is q3-TARGET-91827"},          # case-insensitive
    {"to": "a@company.pl", "body": "x", "Q3-target-91827": 1},            # in a key
])
def test_disclosed_value_copied_into_a_tool_without_max_label_is_denied(args: dict[str, Any]) -> None:
    d = _decide("send_email", args, MAREK, bindings=_disclosed("Q3-target-91827"))
    assert d.verdict == "deny" and d.rule == "egress"


def test_disclosed_number_copied_as_a_json_number_is_denied() -> None:
    assert not _allowed("send_email", {"to": "a@company.pl", "body": "x", "n": 16500},
                        who=MAREK, bindings=_disclosed(16500.0))


def test_disclosed_value_is_matched_as_a_token_only() -> None:
    assert _allowed("create_ticket", {"title": "Room 15"}, who=MAREK, bindings=_disclosed(5))
    assert not _allowed("create_ticket", {"title": "Room 5"}, who=MAREK, bindings=_disclosed(5))


def test_disclosed_value_within_max_label_may_be_copied() -> None:
    assert _allowed("send_email", {"to": "a@company.pl", "body": "Headcount 25"}, bindings=_disclosed(25))
    assert not _allowed("send_email", {"to": "a@company.pl", "body": "Pay 16500"},
                        bindings=_disclosed(16500, "sensitive"))


def test_value_that_was_not_disclosed_is_not_matched() -> None:
    assert _allowed("create_ticket", {"title": "Room 5"}, who=MAREK, bindings={"{x1}": _b("{x1}", "internal", value=5)})


def test_tool_call_ids_are_issued_by_the_gateway(client: TestClient, stub: StubModel, fake_steps: Any) -> None:
    stub.add(tool_call("create_ticket", {"title": "a"}) + tool_call("create_ticket", {"title": "b"}))
    msg = _ask(client, "demo-piotr", [CREATE_TICKET])
    ids = [c["id"] for c in msg["tool_calls"]]
    assert len(set(ids)) == 2 and all(i.startswith("call_") and len(i) == 29 for i in ids)


@pytest.mark.parametrize(("depth", "returned"), [(31, True), (40, False)])
def test_argument_nesting_is_bounded(client: TestClient, stub: StubModel, fake_steps: Any,
                                     depth: int, returned: bool) -> None:
    stub.add(tool_call("create_ticket", '{"title": "t", "x": ' + "[" * depth + "]" * depth + "}"))
    msg = _ask(client, "demo-piotr", [CREATE_TICKET])
    assert bool(msg.get("tool_calls")) is returned
