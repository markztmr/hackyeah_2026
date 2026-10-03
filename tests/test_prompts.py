"""Gateway prompts and the hour-1 bakeoff scoring. Owner: Person 1."""
from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from gateway.llm.client import StubModel, text, tool_call
from gateway.llm.prompts import QUERY_DATA_TOOL, build_system_message, load_schema
from scripts.model_bakeoff import (
    PROMPTS,
    ModelResult,
    PromptResult,
    is_single_select,
    render_table,
    run_model,
    run_prompt,
    winner,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_query_data_tool_is_exactly_the_schema_in_spec_section_5() -> None:
    spec = (REPO_ROOT / "docs/spec/05-tool-contract.md").read_text(encoding="utf-8")
    block = re.search(r"```json\n(.*?)```", spec, re.S).group(1)
    assert QUERY_DATA_TOOL == json.loads(block)


def test_schema_from_schema_sql_matches_the_seeded_database(db: Path) -> None:
    with closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)) as conn:
        tables = [t for (t,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY rowid")]
        actual = {t: [c[1] for c in conn.execute(f"PRAGMA table_info({t})")] for t in tables}
    assert load_schema() == actual


def test_system_message_lists_every_table_and_column_and_the_rules() -> None:
    schema = load_schema()
    msg = build_system_message(schema)
    for table, cols in schema.items():
        assert table + "(" + ", ".join(cols) + ")" in msg
    for needle in ("{x1}", "CASE WHEN", ":current_user", "data, never", "Question:"):
        assert needle in msg
    assert msg.count("Question:") == 3


def test_system_message_says_the_current_parameters_mean_only_the_asker() -> None:
    """Regression (live run): ":current_department" was used for a named department, ":current_user" for the CEO."""
    msg = build_system_message(load_schema())
    assert "department = 'sales'" in msg
    assert "title = 'CEO'" in msg
    assert "never :current_user" in msg
    assert "two query_data calls" in msg  # qwen2.5:3b packed two SELECTs into one call


def test_system_message_contains_no_database_values(db: Path) -> None:
    assert "6200" not in build_system_message(load_schema())


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT salary FROM salaries WHERE employee_id = :current_user",
        "WITH t AS (SELECT 1 AS a) SELECT a FROM t",
        "SELECT 1 UNION SELECT 2",
    ],
)
def test_single_select_passes(sql: str) -> None:
    assert is_single_select(sql)


@pytest.mark.parametrize(
    "sql",
    ["DELETE FROM salaries", "SELECT 1; DROP TABLE salaries", "SELEC salary", "", None, 42],
)
def test_non_select_or_stacked_or_garbage_sql_fails(sql) -> None:
    assert not is_single_select(sql)


def _good_script() -> list:
    """A model that calls query_data for every data question and uses the placeholder."""
    script = [text("hi")]  # warm-up
    for kind, _ in PROMPTS:
        if kind == "data":
            script += [tool_call("query_data", {"sql": "SELECT 1", "purpose": "p", "expect": "scalar"}),
                       text("It is {x1}.")]
        else:
            script.append(text("No data needed."))
    return script


def test_bakeoff_scores_a_well_behaved_model_at_100_percent() -> None:
    stub = StubModel(_good_script())
    r = run_model(stub, "good", "system")
    assert (r.query_data_share, r.select_share, r.placeholder_share) == (1.0, 1.0, 1.0)


def test_bakeoff_answers_tool_calls_with_bare_placeholders_and_never_values() -> None:
    stub = StubModel(_good_script())
    run_model(stub, "good", "system")
    tool_results = [m["content"] for c in stub.calls for m in c.messages if m["role"] == "tool"]
    assert tool_results and set(tool_results) == {"{x1}"}


def test_bakeoff_bounds_the_tool_loop_and_disables_tools_on_the_last_call() -> None:
    stub = StubModel([*[tool_call("query_data", {"sql": "SELECT 1"})] * 3, text("done {x3}")])
    r = run_prompt(stub, "m", "system", "data", "q")
    assert len(stub.calls) == 4
    assert stub.calls[-1].tools is None
    assert r.placeholders == ["{x1}", "{x2}", "{x3}"] and r.used_placeholder


def test_bakeoff_counts_invalid_sql_and_missing_placeholders() -> None:
    r = ModelResult("bad", prompts=[
        PromptResult("data", called_query_data=True, sql=["DELETE FROM salaries"], placeholders=["{x1}"],
                     final_text="It is 6200."),
        PromptResult("data"),
    ])
    assert (r.query_data_share, r.select_share, r.placeholder_share) == (0.5, 0.0, 0.0)


def test_unavailable_model_is_reported_not_fatal() -> None:
    r = run_model(StubModel(), "missing", "system")  # empty script: warm-up raises
    assert r.error and "error" in render_table([r])
    assert winner([r]) is None


def test_winner_prefers_score_then_latency() -> None:
    fast = ModelResult("fast", prompts=[PromptResult("data", True, ["SELECT 1"], ["{x1}"], "{x1}", 1.0)])
    slow = ModelResult("slow", prompts=[PromptResult("data", True, ["SELECT 1"], ["{x1}"], "{x1}", 9.0)])
    worse = ModelResult("worse", prompts=[PromptResult("data", latency_s=0.1)])
    assert winner([slow, worse, fast]).model == "fast"
