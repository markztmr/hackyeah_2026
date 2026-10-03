"""Worked examples from spec section 4, through the full pipeline. Spec section 14 'test_e2e.py'.

Owner: Person 4. The HTTP endpoint, auth, budget, the real validate -> authorize ->
execute -> disclose chain on the seeded database, fill and the output filter all run.
Inbound, judge and issued-value recording are still the ``fake_steps`` stand-ins.
"""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway.agency import loop
from gateway.binding.authorizer import authorize
from gateway.binding.disclosure import disclose
from gateway.binding.executor import execute
from gateway.binding.sql_validator import validate_sql
from gateway.llm.client import StubModel, text, tool_call

SALES_HEADCOUNT = 12
SALES_AVERAGE_SALARY = 9987.5


@pytest.fixture
def real_chain(db: Any, fake_steps: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """The real binding chain and disclosure rule on the seeded database."""
    monkeypatch.setattr(loop, "validate_sql", validate_sql)
    monkeypatch.setattr(loop, "authorize", authorize)
    monkeypatch.setattr(loop, "execute", execute)
    monkeypatch.setattr(loop, "disclose", disclose)


def _query(sql: str) -> Any:
    return tool_call("query_data", {"sql": sql, "purpose": "worked example", "expect": "scalar"})


def _ask(client: TestClient, key: str, question: str) -> Any:
    return client.post("/v1/chat/completions", headers={"Authorization": "Bearer " + key},
                       json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": question}]})


def _tool_results(stub: StubModel, call: int) -> list[str]:
    return [m["content"] for m in stub.calls[call].messages if m.get("role") == "tool"]


def test_worked_example_b_piotr_sees_the_headcount_but_not_the_salary(
    client: TestClient, stub: StubModel, real_chain: None
) -> None:
    """B. Mixed disclosure: headcount (internal) is disclosed, the average salary (sensitive) stays {x2}."""
    stub.add(
        _query("SELECT count(*) FROM employees WHERE department = 'sales'"),
        _query("SELECT avg(s.salary) FROM salaries s JOIN employees e ON e.id = s.employee_id "
               "WHERE e.department = 'sales'"),
        text("Sales has 12 people; their average salary is {x2} PLN."),
    )
    r = _ask(client, "demo-piotr", "How many people work in sales, and what is their average salary?")

    assert r.status_code == 200 and r.headers["x-acl-verdict"] == "allow"
    assert r.json()["choices"][0]["message"]["content"] == (
        "Sales has 12 people; their average salary is " + str(SALES_AVERAGE_SALARY) + " PLN.")

    assert _tool_results(stub, 1) == ["{x1} = " + str(SALES_HEADCOUNT)]   # disclosed
    assert _tool_results(stub, 2)[-1] == "{x2}"                          # bare placeholder
    model_input = "\n".join(str(m.get("content")) for c in stub.calls for m in c.messages)
    assert str(SALES_AVERAGE_SALARY) not in model_input and "9987" not in model_input
