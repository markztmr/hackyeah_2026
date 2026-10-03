"""External answer model: sensitive values never reach it (spec section 5, disclosure rule 4). Owner: Person 1.

``disclose()`` and ``fill()`` have not landed: disclose is replaced with a deliberately
leaky fake (it would reveal every value), so these tests show that the gateway
enforces rule 4 itself; fill is a minimal fake that inserts resolved values.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from gateway import pipeline
from gateway.agency import loop
from gateway.llm.client import StubModel, text, tool_call
from gateway.models import Binding, FilledText, Policy, Principal
from gateway.policy.loader import parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
PIOTR = {"Authorization": "Bearer demo-piotr"}
SALARY = "11500"
SQL = {"sql": "SELECT avg(salary) FROM salaries", "purpose": "average salary", "expect": "scalar"}


def external_example() -> dict[str, Any]:
    """The commented external-model example in policy.yaml, uncommented."""
    lines = (REPO_ROOT / "policy.yaml").read_text(encoding="utf-8").splitlines()
    begin = next(i for i, line in enumerate(lines) if "BEGIN external model example" in line)
    start = next(i for i in range(begin, len(lines)) if re.match(r"^\s*# answer:", lines[i]))
    end = next(i for i, line in enumerate(lines) if "END external model example" in line)
    body = [re.sub(r"^\s*# ?", "", line, count=1) for line in lines[start:end]]
    return yaml.safe_load("\n".join(body))


def _external_policy_yaml(trust: str = "external") -> dict[str, Any]:
    data = copy.deepcopy(yaml.safe_load((REPO_ROOT / "policy.yaml").read_text(encoding="utf-8")))
    example = external_example()
    data["models"]["answer"] = example["answer"]
    data["models"]["answer"]["trust"] = trust
    data["models"]["allowed"].extend(example["allowed"])
    # Isolate rule 4: let HR send sensitive values to a model, so only trust can hide them.
    data["roles"]["hr_manager"]["max_label_to_model"] = "sensitive"
    return data


# ---------------------------------------------------------------------------
# The example in policy.yaml
# ---------------------------------------------------------------------------


def test_commented_external_example_is_a_valid_policy() -> None:
    p = parse_policy(yaml.safe_dump(_external_policy_yaml()).encode())
    answer = p.tree["models"]["answer"]
    assert (answer["provider"], answer["trust"]) == ("openai_compatible", "external")
    assert answer["name"] in {m["name"] for m in p.tree["models"]["allowed"]}


def test_shipped_policy_still_uses_the_local_model() -> None:
    p = parse_policy((REPO_ROOT / "policy.yaml").read_bytes())
    assert p.tree["models"]["answer"]["trust"] == "local"


def test_example_never_holds_an_api_key() -> None:
    assert "api_key" not in yaml.safe_dump(external_example()["answer"])


# ---------------------------------------------------------------------------
# The loop passes trust to disclose() and enforces rule 4 itself
# ---------------------------------------------------------------------------


@pytest.fixture
def leaky_disclose(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """A disclose() that would show every value; records the trust it was given."""
    calls: list[dict[str, Any]] = []

    def disclose(b: Binding, p: Principal, policy: Policy, *, trust: str) -> str:
        calls.append({"name": b.name, "trust": trust})
        return f"{b.name} = {b.value}"

    monkeypatch.setattr(loop, "disclose", disclose)
    return calls


@pytest.fixture
def salary_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    def execute(b: Binding, p: Principal, policy: Policy) -> Binding:
        b.status, b.value, b.label = "resolved", SALARY, "sensitive"
        return b

    monkeypatch.setattr(loop, "execute", execute)


@pytest.fixture
def filling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Minimal stand-in for outbound fill: resolved values in one regex pass, markers otherwise."""
    def fill(t: str, bindings: dict[str, Binding], vault: Any, policy: Policy) -> FilledText:
        def one(m: re.Match[str]) -> str:
            b = bindings.get(m.group(0))
            return str(b.value) if b is not None and b.status == "resolved" else "[UNAVAILABLE]"
        return FilledText(text=re.sub(r"\{x\d+\}", one, t))

    monkeypatch.setattr(pipeline, "fill", fill)


def _use_policy(path: Path, data: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def test_trust_is_passed_to_disclose(
    client: TestClient, stub: StubModel, fake_steps, policy: Path, leaky_disclose: list[dict[str, Any]],
) -> None:
    _use_policy(policy, _external_policy_yaml())
    stub.add(tool_call("query_data", SQL), text("{x1}"))  # fake execute: public value 1
    client.post("/v1/chat/completions", json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Count?"}]}, headers=PIOTR)
    assert leaky_disclose == [{"name": "{x1}", "trust": "external"}]


def test_external_model_never_sees_a_sensitive_value_but_the_user_gets_it(
    client: TestClient, stub: StubModel, judge_stub: StubModel, fake_steps, policy: Path,
    leaky_disclose: list[dict[str, Any]], salary_binding: None, filling: None,
    all_model_inputs, audit_records,
) -> None:
    _use_policy(policy, _external_policy_yaml())
    stub.add(tool_call("query_data", SQL), text("The average salary is {x1} PLN."))
    r = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "What is the average salary?"}]},
        headers=PIOTR,
    )

    assert r.status_code == 200
    assert r.json()["choices"][0]["message"]["content"] == f"The average salary is {SALARY} PLN."
    assert SALARY not in all_model_inputs(stub, judge_stub)
    assert leaky_disclose == []  # the gateway never even asked disclose() to reveal it
    (record,) = audit_records()
    assert record["bindings"][0]["disclosed"] is False


def test_local_model_lets_disclose_decide(
    client: TestClient, stub: StubModel, judge_stub: StubModel, fake_steps, policy: Path,
    leaky_disclose: list[dict[str, Any]], salary_binding: None, filling: None, all_model_inputs,
) -> None:
    """Control case: same request with trust local. Proves the test above detects a leak."""
    _use_policy(policy, _external_policy_yaml(trust="local"))
    stub.add(tool_call("query_data", SQL), text("{x1}"))
    client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Average salary?"}]},
        headers=PIOTR,
    )
    assert leaky_disclose == [{"name": "{x1}", "trust": "local"}]
    assert SALARY in all_model_inputs(stub, judge_stub)


@pytest.mark.parametrize("label", ["sensitive", None, "unknown"])
def test_external_trust_hides_sensitive_or_unlabelled_values(
    label: Any, leaky_disclose: list[dict[str, Any]],
) -> None:
    p = parse_policy(yaml.safe_dump(_external_policy_yaml()).encode())
    b = Binding(name="{x1}", sql="SELECT 1", purpose="t", expect="scalar", status="resolved", value=SALARY, label=label)
    assert loop._tool_result(b, Principal("piotr", "hr_manager", "hr", "allow"), p, "external") == "{x1}"
    assert leaky_disclose == []


@pytest.mark.parametrize("label", ["public", "internal"])
def test_external_trust_still_asks_disclose_for_lower_labels(label: str, leaky_disclose: list[dict[str, Any]]) -> None:
    p = parse_policy(yaml.safe_dump(_external_policy_yaml()).encode())
    b = Binding(name="{x1}", sql="SELECT 1", purpose="t", expect="scalar", status="resolved", value="12", label=label)  # type: ignore[arg-type]
    assert loop._tool_result(b, Principal("piotr", "hr_manager", "hr", "allow"), p, "external") == "{x1} = 12"
    assert leaky_disclose == [{"name": "{x1}", "trust": "external"}]
