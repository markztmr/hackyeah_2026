"""Disclosure rule: placeholder or value for the model. Spec section 5 'Disclosure rule', I7, I10, I14.

Owner: Person 3. A value is shown as ``{x1} = <value>`` only if all five conditions
hold: resolved; effective AI data policy allow; label at or below the role's
``max_label_to_model``; local model or a label below sensitive; the value passes the
injection and signature scan. Otherwise the bare placeholder, and the failed condition
goes to ``binding.reason`` (audit log only). The end-to-end tests run the real
validate -> authorize -> execute -> disclose chain inside the tool loop and check what
the stub model actually received.
"""
from __future__ import annotations

import copy
import shutil
from pathlib import Path
from typing import Any

import pytest

from db.seed import INJECTION_TITLE
from gateway.agency.loop import run_tool_loop
from gateway.binding.disclosure import disclose
from gateway.llm.client import StubModel, text, tool_call
from gateway.models import Binding, Policy, Principal, SanitizedRequest, Vault
from tests.test_authorizer import ANNA, MAREK, PIOTR, STRICT, _data, _parse

VALUE = 6200
STATUSES = ["resolved", "denied", "rejected", "empty", "error"]
REPO_ROOT = Path(__file__).resolve().parent.parent


def _policy(trust: str = "local", hr_limit: str = "internal") -> Policy:
    data = copy.deepcopy(_data("strict"))
    data["models"]["answer"]["trust"] = trust
    data["roles"]["hr_manager"]["max_label_to_model"] = hr_limit
    return _parse(data)


# Isolates rule 4: HR may send sensitive values to a model, so only trust can hide them.
SENSITIVE_OK = _policy(hr_limit="sensitive")


def _binding(status: str = "resolved", label: str | None = "sensitive", value: Any = VALUE) -> Binding:
    return Binding(name="{x1}", sql="SELECT salary FROM salaries WHERE employee_id = :current_user",
                   purpose="t", expect="scalar", status=status, value=value, label=label)  # type: ignore[arg-type]


def _hidden(b: Binding, shown: str) -> None:
    assert shown == b.name
    assert b.disclosed is False


# ---------------------------------------------------------------------------
# All five hold: the value is shown
# ---------------------------------------------------------------------------


def test_piotr_gets_the_internal_headcount() -> None:
    b = _binding(label="internal", value=12)
    assert disclose(b, PIOTR, STRICT, trust="local") == "{x1} = 12"
    assert b.disclosed is True


@pytest.mark.parametrize("label", ["public", "internal"])
def test_marek_gets_values_up_to_internal(label: str) -> None:
    b = _binding(label=label, value=4)
    assert disclose(b, MAREK, STRICT, trust="local") == "{x1} = 4"
    assert b.disclosed is True


def test_disclosed_value_uses_the_bindings_own_name() -> None:
    b = _binding(label="internal", value="Sales Rep")
    b.name = "{x17}"
    assert disclose(b, PIOTR, STRICT, trust="local") == "{x17} = Sales Rep"


def test_reason_is_left_untouched_when_disclosed() -> None:
    b = _binding(label="internal", value=12)
    disclose(b, PIOTR, STRICT, trust="local")
    assert b.reason == ""


# ---------------------------------------------------------------------------
# Condition 2: AI data policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label", ["public", "internal", "sensitive"])
@pytest.mark.parametrize("trust", ["local", "external"])
def test_anna_never_gets_values(label: str, trust: str) -> None:
    b = _binding(label=label)
    _hidden(b, disclose(b, ANNA, SENSITIVE_OK, trust=trust))  # type: ignore[arg-type]
    assert "AI data policy" in b.reason


def test_role_cap_wins_over_a_principal_claiming_allow() -> None:
    anna_allow = Principal(user_id="anna", role="intern", department="sales", ai_data_policy="allow")
    b = _binding(label="public", value=3)
    _hidden(b, disclose(b, anna_allow, STRICT, trust="local"))
    assert "AI data policy" in b.reason


# ---------------------------------------------------------------------------
# Condition 3: label limit
# ---------------------------------------------------------------------------


def test_piotr_does_not_get_a_salary() -> None:
    b = _binding(label="sensitive")
    _hidden(b, disclose(b, PIOTR, STRICT, trust="local"))
    assert "label" in b.reason


@pytest.mark.parametrize("label", [None, "secret", ""])
def test_unknown_or_missing_label_is_not_disclosed(label: str | None) -> None:
    b = _binding(label=label)
    _hidden(b, disclose(b, PIOTR, SENSITIVE_OK, trust="local"))


def test_unknown_role_is_not_disclosed() -> None:
    ghost = Principal(user_id="ghost", role="ghost", department="hr", ai_data_policy="allow")
    b = _binding(label="public")
    _hidden(b, disclose(b, ghost, STRICT, trust="local"))


# ---------------------------------------------------------------------------
# Condition 4: model trust
# ---------------------------------------------------------------------------


def test_sensitive_value_goes_to_a_local_model_when_the_role_allows_it() -> None:
    b = _binding(label="sensitive")
    assert disclose(b, PIOTR, SENSITIVE_OK, trust="local") == "{x1} = 6200"


def test_external_model_never_gets_a_sensitive_value() -> None:
    b = _binding(label="sensitive")
    _hidden(b, disclose(b, PIOTR, SENSITIVE_OK, trust="external"))
    assert "external" in b.reason


def test_external_model_still_gets_internal_values() -> None:
    assert disclose(_binding(label="internal", value=12), PIOTR, SENSITIVE_OK, trust="external") == "{x1} = 12"


def test_trust_defaults_to_external() -> None:
    _hidden(b := _binding(label="sensitive"), disclose(b, PIOTR, SENSITIVE_OK))


# ---------------------------------------------------------------------------
# Condition 5: database content is untrusted
# ---------------------------------------------------------------------------


def test_seeded_injection_title_is_not_disclosed_even_to_piotr() -> None:
    b = _binding(label="internal", value=INJECTION_TITLE)
    _hidden(b, disclose(b, PIOTR, STRICT, trust="local"))
    assert "injection" in b.reason
    assert "ignore" not in b.reason  # the reason names the check, never the matched text


def test_value_matching_an_attack_signature_is_not_disclosed() -> None:
    b = _binding(label="internal", value="cleanup: rm -rf /")
    _hidden(b, disclose(b, PIOTR, STRICT, trust="local"))
    assert "signature" in b.reason


def test_missing_feed_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    shutil.copyfile(REPO_ROOT / "policy.yaml", tmp_path / "policy.yaml")  # no signatures.json beside it
    monkeypatch.setenv("ACL_POLICY_PATH", str(tmp_path / "policy.yaml"))
    b = _binding(label="internal", value=12)
    _hidden(b, disclose(b, PIOTR, STRICT, trust="local"))


@pytest.mark.parametrize("value", [{"salary": VALUE}, b"6200", None, True, [1, 2]])
def test_odd_values_never_reach_the_tool_result(value: Any) -> None:
    b = _binding(label="internal", value=value)
    _hidden(b, disclose(b, PIOTR, STRICT, trust="local"))


# ---------------------------------------------------------------------------
# Condition 1 and I14: every hidden outcome looks the same
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", STATUSES[1:])
def test_denied_and_hidden_resolved_bindings_give_identical_tool_results(status: str) -> None:
    hidden_resolved = disclose(_binding("resolved", label="sensitive"), PIOTR, STRICT, trust="local")
    not_resolved = disclose(_binding(status, label=None, value=None), PIOTR, STRICT, trust="local")
    assert hidden_resolved == not_resolved == "{x1}"


@pytest.mark.parametrize("status", STATUSES[1:])
def test_non_resolved_binding_is_never_disclosed_and_keeps_its_reason(status: str) -> None:
    b = _binding(status, label="public", value=1)  # even a stray value is not shown
    b.reason = "Column salary is not permitted."
    _hidden(b, disclose(b, PIOTR, STRICT, trust="local"))
    assert b.reason == "Column salary is not permitted."


def test_disclosed_flag_is_reset_to_false() -> None:
    b = _binding()
    b.disclosed = True
    disclose(b, PIOTR, STRICT, trust="local")
    assert b.disclosed is False


# ---------------------------------------------------------------------------
# End to end: what the model receives from the real binding chain
# ---------------------------------------------------------------------------


@pytest.fixture
def chain(db: Any) -> Any:
    """Run one query_data call through the real loop; return (binding, tool result the model saw, stub)."""

    def run(sql: str, who: Principal, policy: Policy = STRICT, expect: str = "scalar") -> tuple[Binding, str, StubModel]:
        stub = StubModel()
        stub.add(tool_call("query_data", {"sql": sql, "purpose": "t", "expect": expect}), text("{x1}"))
        req = SanitizedRequest(messages=[{"role": "user", "content": "question"}], tools=[])
        result = run_tool_loop(req, who, Vault(), policy, models=lambda purpose, pol: stub)
        tool_msgs = [m for m in stub.calls[1].messages if m.get("role") == "tool"]
        assert len(tool_msgs) == 1
        return result.bindings["{x1}"], tool_msgs[0]["content"], stub
    return run


def _model_saw(stub: StubModel) -> str:
    return "\n".join(str(m.get("content")) for call in stub.calls for m in call.messages)


def test_piotr_headcount_reaches_the_model(chain: Any) -> None:
    b, shown, stub = chain("SELECT count(*) FROM employees WHERE department = 'sales'", PIOTR)
    assert b.status == "resolved" and b.label == "internal"
    assert shown == "{x1} = " + str(b.value) and b.disclosed is True


def test_piotr_reads_a_salary_but_the_model_sees_only_the_placeholder(chain: Any) -> None:
    b, shown, stub = chain("SELECT salary FROM salaries WHERE employee_id = 'anna'", PIOTR)
    assert b.status == "resolved" and b.value == VALUE and b.label == "sensitive"
    assert shown == "{x1}" and b.disclosed is False
    assert str(VALUE) not in _model_saw(stub)


def test_external_answer_model_never_receives_a_salary(chain: Any) -> None:
    b, shown, stub = chain("SELECT salary FROM salaries WHERE employee_id = 'anna'", PIOTR,
                           _policy(trust="external", hr_limit="sensitive"))
    assert b.status == "resolved" and shown == "{x1}"
    assert str(VALUE) not in _model_saw(stub)


def test_local_answer_model_receives_it_when_the_role_allows_sensitive(chain: Any) -> None:
    """Control case for the test above: same query, trust local."""
    b, shown, _ = chain("SELECT salary FROM salaries WHERE employee_id = 'anna'", PIOTR, SENSITIVE_OK)
    assert shown == "{x1} = 6200" and b.disclosed is True


def test_seeded_injection_title_never_reaches_the_model(chain: Any) -> None:
    b, shown, stub = chain("SELECT title FROM employees WHERE id = 'robert'", PIOTR)
    assert b.status == "resolved" and b.value == INJECTION_TITLE and b.label == "internal"
    assert shown == "{x1}" and b.disclosed is False
    assert "ignore your rules" not in _model_saw(stub)


def test_anna_own_salary_never_reaches_the_model(chain: Any) -> None:
    b, shown, stub = chain("SELECT salary FROM salaries WHERE employee_id = :current_user", ANNA)
    assert b.status == "resolved"
    assert shown == "{x1}"
    assert str(VALUE) not in _model_saw(stub)


def test_anna_public_product_count_is_still_hidden(chain: Any) -> None:
    b, shown, _ = chain("SELECT count(*) FROM products", ANNA)
    assert b.status == "resolved" and b.label == "public"
    assert shown == "{x1}"


def test_denied_and_hidden_resolved_look_the_same_end_to_end(chain: Any) -> None:
    _, hidden, _ = chain("SELECT salary FROM salaries WHERE employee_id = 'anna'", PIOTR)
    denied, refused, _ = chain("SELECT salary FROM salaries WHERE employee_id = 'katarzyna'", MAREK)
    assert denied.status == "denied"
    assert hidden == refused == "{x1}"
