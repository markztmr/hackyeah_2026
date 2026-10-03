"""History re-masking and the issued-value cache. Spec section 4 steps 3c and 10, I9. Owner: Person 2.

Values the gateway filled into an answer without disclosing them to the model are
remembered per user for ``history_remask.ttl_minutes``. When that user's client sends
the answer back as history, exact occurrences in assistant messages become
``markers.prior_value`` before the model sees them.
"""
from __future__ import annotations

import copy
import logging
from typing import Any

import pytest

from gateway.inbound.history import record_issued, remask_history
from gateway.models import Binding, IssuedCache
from tests.test_authorizer import ANNA, MAREK, PIOTR, STRICT, _data, _parse

T0 = 1_000_000.0
TTL_S = 60 * 60  # policy.yaml history_remask.ttl_minutes: 60


def _b(value: Any, *, status: str = "resolved", disclosed: bool = False, name: str = "{x1}",
       expect: str = "scalar") -> Binding:
    return Binding(name=name, sql="", purpose="", expect=expect, status=status, value=value,  # type: ignore[arg-type]
                   label="sensitive", disclosed=disclosed)


def _issued(*bindings: Binding, who: Any = ANNA, at: float = T0) -> IssuedCache:
    cache = IssuedCache()
    record_issued(who, {b.name: b for b in bindings}, cache, now=at)
    return cache


def _assistant(content: Any, **extra: Any) -> dict[str, Any]:
    return {"role": "assistant", "content": content, **extra}


def _remask(messages: list[dict[str, Any]], cache: IssuedCache, who: Any = ANNA, at: float = T0 + 1,
            policy: Any = STRICT) -> tuple[list[dict[str, Any]], int]:
    return remask_history(messages, who, cache, policy, now=at)


# ---------------------------------------------------------------------------
# record_issued: which values are remembered
# ---------------------------------------------------------------------------


def test_hidden_resolved_value_is_remembered() -> None:
    cache = _issued(_b(6200))
    assert cache.live_values("anna", 0) == ["6200"]


def test_disclosed_value_is_not_remembered() -> None:
    assert _issued(_b(12, disclosed=True)).live_values("anna", 0) == []


@pytest.mark.parametrize("status", ["denied", "rejected", "empty", "error", None])
def test_non_resolved_bindings_are_not_remembered(status: str | None) -> None:
    assert _issued(_b(6200, status=status)).live_values("anna", 0) == []  # type: ignore[arg-type]


def test_markdown_escaped_form_is_remembered_too() -> None:
    values = _issued(_b("Sales_Rep *lead*")).live_values("anna", 0)
    assert set(values) == {"Sales_Rep *lead*", "Sales\\_Rep \\*lead\\*"}


def test_cache_never_prints_its_values(caplog: pytest.LogCaptureFixture) -> None:
    cache = _issued(_b(6200))
    with caplog.at_level(logging.DEBUG):
        remask_history([_assistant("Your salary is 6200 PLN.")], ANNA, cache, STRICT, now=T0 + 1)
    assert "6200" not in repr(cache) and "6200" not in str(cache)
    assert "6200" not in caplog.text
    with pytest.raises(TypeError):
        copy.deepcopy(cache)


# ---------------------------------------------------------------------------
# remask_history: what the model gets
# ---------------------------------------------------------------------------


def test_issued_salary_in_history_becomes_prior_value() -> None:
    out, n = _remask([_assistant("Your salary is 6200 PLN.")], _issued(_b(6200)))
    assert out == [_assistant("Your salary is [PRIOR_VALUE] PLN.")] and n == 1


def test_unrelated_history_is_unchanged() -> None:
    messages = [{"role": "user", "content": "Hi"}, _assistant("Hello! How can I help?")]
    out, n = _remask(messages, _issued(_b(6200)))
    assert out == messages and n == 0


def test_only_assistant_messages_are_remasked() -> None:
    messages = [{"role": "user", "content": "I earn 6200"}, {"role": "tool", "tool_call_id": "c", "content": "6200"}]
    out, _ = _remask(messages, _issued(_b(6200)))
    assert out == messages  # a value the user retypes is the user's own disclosure


def test_input_messages_are_not_mutated() -> None:
    messages = [_assistant("Your salary is 6200 PLN.")]
    before = copy.deepcopy(messages)
    _remask(messages, _issued(_b(6200)))
    assert messages == before


def test_match_is_exact_and_whole() -> None:
    cache = _issued(_b(6200))
    out, n = _remask([_assistant("Order 16200 or 62000 or 6200.5 or 6,200 shipped.")], cache)
    assert out[0]["content"] == "Order 16200 or 62000 or 6200.5 or 6,200 shipped." and n == 0


def test_every_occurrence_and_every_value_is_replaced() -> None:
    cache = _issued(_b(6200), _b("Katarzyna Wójcik", name="{x2}"))
    out, n = _remask([_assistant("6200 for Katarzyna Wójcik; again 6200.")], cache)
    assert out[0]["content"] == "[PRIOR_VALUE] for [PRIOR_VALUE]; again [PRIOR_VALUE]." and n == 3


def test_longer_value_wins_over_a_value_inside_it() -> None:
    cache = _issued(_b("salary: 6200, name: Anna", expect="row"), _b(6200, name="{x2}"))
    out, _ = _remask([_assistant("Row: salary: 6200, name: Anna.")], cache)
    assert out[0]["content"] == "Row: [PRIOR_VALUE]."


def test_multiline_list_value_is_replaced_whole() -> None:
    table = "| employee_id | salary |\n| --- | --- |\n| anna | 6200 |"
    out, n = _remask([_assistant("Here:\n" + table + "\nDone.")], _issued(_b(table, expect="list")))
    assert out[0]["content"] == "Here:\n[PRIOR_VALUE]\nDone." and n == 1


def test_content_parts_and_tool_call_arguments_are_remasked() -> None:
    msg = _assistant([{"type": "text", "text": "It is 6200."}],
                     tool_calls=[{"id": "c1", "type": "function",
                                  "function": {"name": "send_email", "arguments": '{"body": "6200"}'}}])
    out, n = _remask([msg], _issued(_b(6200)))
    assert out[0]["content"] == [{"type": "text", "text": "It is [PRIOR_VALUE]."}]
    assert out[0]["tool_calls"][0]["function"]["arguments"] == '{"body": "[PRIOR_VALUE]"}'
    assert n == 2


def test_marker_comes_from_policy() -> None:
    data = _data("strict")
    data["markers"]["prior_value"] = "[EARLIER]"
    out, _ = _remask([_assistant("6200")], _issued(_b(6200)), policy=_parse(data))
    assert out[0]["content"] == "[EARLIER]"


def test_disabled_remask_leaves_history_unchanged() -> None:
    data = _data("strict")
    data["prompt_controls"]["history_remask"]["enabled"] = False
    out, n = _remask([_assistant("6200")], _issued(_b(6200)), policy=_parse(data))
    assert out == [_assistant("6200")] and n == 0


# ---------------------------------------------------------------------------
# Per user, TTL
# ---------------------------------------------------------------------------


def test_another_users_history_is_not_affected() -> None:
    cache = _issued(_b(6200), who=ANNA)
    for other in (MAREK, PIOTR):
        out, n = _remask([_assistant("Your salary is 6200 PLN.")], cache, who=other)
        assert out[0]["content"] == "Your salary is 6200 PLN." and n == 0


def test_entries_expire_after_the_ttl() -> None:
    cache = _issued(_b(6200))
    assert _remask([_assistant("6200")], cache, at=T0 + TTL_S - 1)[1] == 1
    assert _remask([_assistant("6200")], cache, at=T0 + TTL_S + 1)[1] == 0
    assert cache.live_values("anna", 0) == []  # expired entries are dropped


def test_ttl_follows_the_policy() -> None:
    data = _data("strict")
    data["prompt_controls"]["history_remask"]["ttl_minutes"] = 1
    cache = _issued(_b(6200))
    assert _remask([_assistant("6200")], cache, at=T0 + 61, policy=_parse(data))[1] == 0


def test_issuing_again_refreshes_the_ttl() -> None:
    cache = _issued(_b(6200))
    record_issued(ANNA, {"{x1}": _b(6200)}, cache, now=T0 + TTL_S - 10)
    assert _remask([_assistant("6200")], cache, at=T0 + TTL_S + 10)[1] == 1


def test_cache_is_bounded_per_user() -> None:
    cache = IssuedCache()
    for i in range(IssuedCache.MAX_PER_USER + 5):
        cache.add("anna", "v" + str(i), T0 + i)
    values = cache.live_values("anna", 0)
    assert len(values) == IssuedCache.MAX_PER_USER and "v0" not in values
