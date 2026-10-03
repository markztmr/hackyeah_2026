"""Outbound fill: single literal pass, markers, escaping, echo of own input, spans.

Spec section 4 step 8, section 5 'Placeholder rules' and 'Outcomes and markers', I13, I14.
Owner: Person 3.
"""
from __future__ import annotations

from typing import Any

import pytest

from gateway.models import Binding, FilledText, Policy, Vault
from gateway.outbound.fill import fill
from gateway.outbound.output_filter import filter_output
from tests.test_authorizer import ANNA, STRICT, _data, _parse

UNAVAILABLE = "[UNAVAILABLE]"


def _profile_policy(profile: str) -> Policy:
    """policy.yaml sets markers and echo_own_input explicitly; drop them so the profile decides."""
    data = _data(profile)
    del data["markers"]
    data["output_controls"].pop("echo_own_input", None)
    return _parse(data)


BALANCED = _profile_policy("balanced")


def _b(name: str = "{x1}", status: str | None = "resolved", value: Any = 6200, expect: str = "scalar") -> Binding:
    return Binding(name=name, sql="SELECT 1", purpose="t", expect=expect,  # type: ignore[arg-type]
                   status=status, value=value if status == "resolved" else None)  # type: ignore[arg-type]


def _fill(text: str, *bindings: Binding, policy: Policy = STRICT, vault: Vault | None = None) -> FilledText:
    return fill(text, {b.name: b for b in bindings}, vault or Vault(), policy)


def _gateway(f: FilledText) -> list[str]:
    return [f.text[s.start:s.end] for s in f.spans if s.source == "gateway"]


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------


def test_value_is_inserted_for_each_occurrence() -> None:
    f = _fill("Your salary is {x1} PLN. Again: {x1}.", _b())
    assert f.text == "Your salary is 6200 PLN. Again: 6200."
    assert [s.binding for s in f.spans if s.source == "gateway"] == ["{x1}", "{x1}"]


def test_seeded_name_containing_a_placeholder_is_inserted_literally() -> None:
    f = _fill("Name: {x1}.", _b("{x1}", value="Jan {x2} Kowalski"), _b("{x2}", value=48000))
    assert f.text == "Name: Jan {x2} Kowalski."
    assert "48000" not in f.text


def test_value_referring_to_itself_is_not_expanded_again() -> None:
    assert _fill("{x1}", _b(value="{x1}{x1}")).text == "{x1}{x1}"


def test_value_with_format_syntax_is_inserted_literally() -> None:
    assert _fill("{x1}", _b(value="{0} {name} %s {{x}}")).text == "{0} {name} %s {{x}}"


def test_script_in_a_value_is_escaped() -> None:
    f = _fill("Product: {x1}", _b(value="<script>alert(1)</script> Gift Card"))
    assert "<script>" not in f.text
    assert "&lt;script&gt;" in f.text


def test_markdown_in_a_value_is_escaped() -> None:
    f = _fill("{x1}", _b(value="*bold* _it_ [link](http://evil) `code` # h | ~s~ \\"))
    for raw in ("*bold*", "_it_", "[link]", "`code`"):
        assert raw not in f.text
    assert f.text.startswith("\\*bold\\*")


def test_escape_none_inserts_values_as_they_are() -> None:
    data = _data()
    data["output_controls"]["escape"] = "none"
    f = _fill("{x1}", _b(value="<b>*x*</b>"), policy=_parse(data))
    assert f.text == "<b>*x*</b>"


def test_list_value_is_already_a_markdown_table_and_is_not_escaped_again() -> None:
    table = "| name |\n| --- |\n| a \\| b |"
    assert _fill("{x1}", _b(value=table, expect="list")).text == table


def test_numbers_are_inserted_as_text() -> None:
    assert _fill("{x1} / {x2}", _b("{x1}", value=12), _b("{x2}", value=7499.5)).text == "12 / 7499.5"


# ---------------------------------------------------------------------------
# Markers
# ---------------------------------------------------------------------------


def test_placeholder_without_a_binding_becomes_the_unavailable_marker() -> None:
    assert _fill("Salary: {x9}.", _b()).text == f"Salary: {UNAVAILABLE}."
    assert _fill("Salary: {x9}.", _b(), policy=BALANCED).text == f"Salary: {UNAVAILABLE}."


@pytest.mark.parametrize("text", ['{"a": 1}', "{x}", "{X1}", "{y1}", "{ x1 }", "{x1a}", "x1", "{x-1}", "{}"])
def test_ordinary_braces_are_untouched(text: str) -> None:
    assert _fill(text, _b()).text == text


def test_strict_uses_one_marker_for_every_non_resolved_outcome() -> None:
    bindings = [_b(f"{{x{i}}}", status=s) for i, s in enumerate(["denied", "rejected", "empty", "error"], 1)]
    f = _fill("{x1} {x2} {x3} {x4}", *bindings, policy=_profile_policy("strict"))
    assert f.text == " ".join([UNAVAILABLE] * 4)


def test_balanced_uses_distinct_markers() -> None:
    bindings = [_b(f"{{x{i}}}", status=s) for i, s in enumerate(["denied", "rejected", "empty", "error"], 1)]
    f = _fill("{x1} {x2} {x3} {x4}", *bindings, policy=BALANCED)
    assert f.text == "[NOT AUTHORIZED] [UNAVAILABLE] [NO DATA] [UNAVAILABLE]"


def test_binding_that_never_finished_gets_the_unavailable_marker() -> None:
    assert _fill("{x1}", _b(status=None)).text == UNAVAILABLE


def test_resolved_binding_without_a_value_gets_the_unavailable_marker() -> None:
    b = _b()
    b.value = None
    assert _fill("{x1}", b).text == UNAVAILABLE


# ---------------------------------------------------------------------------
# all_denied_message
# ---------------------------------------------------------------------------


def _with_message(message: str | None = "I cannot share that information.") -> Policy:
    data = _data()
    data["markers"]["all_denied_message"] = message
    return _parse(data)


def test_all_denied_message_replaces_an_answer_where_every_binding_is_non_resolved() -> None:
    f = _fill("Your salary is {x1}, the CEO earns {x2}.", _b("{x1}", "denied"), _b("{x2}", "empty"),
              policy=_with_message())
    assert f.text == "I cannot share that information."
    assert _gateway(f) == [f.text]


def test_all_denied_message_is_not_used_when_one_binding_resolved() -> None:
    f = _fill("{x1} {x2}", _b("{x1}"), _b("{x2}", "denied"), policy=_with_message())
    assert f.text == f"6200 {UNAVAILABLE}"


def test_all_denied_message_is_not_used_for_text_without_placeholders() -> None:
    assert _fill("Hello.", _b("{x1}", "denied"), policy=_with_message()).text == "Hello."


def test_without_all_denied_message_markers_stay_in_the_sentence() -> None:
    assert _fill("Salary: {x1}.", _b("{x1}", "denied")).text == f"Salary: {UNAVAILABLE}."


# ---------------------------------------------------------------------------
# The user's own mask tokens (echo_own_input)
# ---------------------------------------------------------------------------


def _vault() -> Vault:
    v = Vault()
    v.add_mask("[EMAIL_1]", "anna.zielinska@company.pl")
    return v


def test_strict_leaves_the_users_mask_token_in_place() -> None:
    assert _fill("Sent to [EMAIL_1].", vault=_vault()).text == "Sent to [EMAIL_1]."


def test_echo_own_input_restores_the_users_mask_token_as_a_gateway_span() -> None:
    f = _fill("Sent to [EMAIL_1].", vault=_vault(), policy=BALANCED)
    assert f.text == "Sent to anna.zielinska@company.pl."
    assert _gateway(f) == ["anna.zielinska@company.pl"]
    assert [s.binding for s in f.spans if s.source == "gateway"] == [None]


def test_unknown_mask_token_is_left_as_it_is() -> None:
    assert _fill("[EMAIL_9] [SECRET_1]", vault=_vault(), policy=BALANCED).text == "[EMAIL_9] [SECRET_1]"


def test_restored_input_is_escaped() -> None:
    v = Vault()
    v.add_mask("[SECRET_1]", "<img src=x>")
    assert "<img" not in _fill("[SECRET_1]", vault=v, policy=BALANCED).text


def test_mask_token_inside_an_inserted_value_is_not_restored() -> None:
    f = _fill("{x1}", _b(value="[EMAIL_1]"), vault=_vault(), policy=BALANCED)
    assert "company.pl" not in f.text
    assert "EMAIL\\_1" in f.text  # inserted literally (escaped), never re-scanned


# ---------------------------------------------------------------------------
# Spans
# ---------------------------------------------------------------------------


def test_spans_cover_the_text_and_mark_who_wrote_each_part() -> None:
    f = _fill("A {x1} B {x9} C", _b())
    assert f.text == f"A 6200 B {UNAVAILABLE} C"
    parts = [(f.text[s.start:s.end], s.source, s.binding) for s in sorted(f.spans, key=lambda s: s.start)]
    assert parts == [("A ", "model", None), ("6200", "gateway", "{x1}"), (" B ", "model", None),
                     (UNAVAILABLE, "gateway", None), (" C", "model", None)]


def test_text_without_placeholders_is_one_model_span() -> None:
    f = _fill("Just text.", _b())
    assert [(s.start, s.end, s.source) for s in f.spans] == [(0, 10, "model")]


def test_empty_text() -> None:
    f = _fill("", _b())
    assert f.text == "" and f.spans == []


def test_output_filter_keeps_an_inserted_email_but_redacts_one_the_model_wrote() -> None:
    f = _fill("Email: {x1}. Also katarzyna.nowak@company.pl", _b(value="piotr.grabowski@company.pl"))
    answer, _ = filter_output(f, ANNA, STRICT)
    assert "piotr.grabowski@company.pl" in answer
    assert "katarzyna.nowak@company.pl" not in answer
