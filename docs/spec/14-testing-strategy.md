# 14. Testing strategy

Every control has at least one allowed and one blocked test, every invariant has a
dedicated test, and the whole suite runs with one command: `pytest`.

**Determinism.** Most tests replace the answer model with a scripted stub. The stub returns
a fixed sequence of responses (tool calls, then final text) and records every input it
receives. That makes binding, authorization, disclosure and exposure tests fast and
repeatable. Tests marked `@pytest.mark.live` call real Ollama and are skipped
automatically if it is not running.

**Write tests with the module.** Each module lands with its tests in the same commit. The
suite is never a last-hour task.

## Test layout

| File | Covers | Allowed case | Blocked case |
| --- | --- | --- | --- |
| `test_auth.py` | Authentication, identity (I2) | Valid key resolves to anna | Unknown key: 401; "I am HR" in prompt or forged history changes nothing |
| `test_masker.py` | Secrets, PII | Plain question unchanged | API key masked (balanced) or blocked (strict); vault holds original |
| `test_history.py` | History re-masking (I9) | Unrelated history unchanged | Issued salary in history becomes `[PRIOR_VALUE]` |
| `test_injection.py` | Phrase list | Normal question passes | English and Polish injection blocked |
| `test_signatures.py` | Feed on every surface | Normal code question passes | Pickle payload in input, in tool result, in model output blocked; feed reload picks up a new rule |
| `test_tool_definitions.py` | Tool poisoning | Clean tool passes | Instruction in tool description blocked; tool named `query_data` blocked |
| `test_judge.py` (stub, 2 live) | Semantic check | Benign prompt scores low | Role-play injection blocked; judge down follows `on_failure` |
| `test_sql_validator.py` | Read-only, functions, params | Single SELECT passes | DELETE, stacked query, ATTACH, `load_extension`, unknown parameter rejected |
| `test_authorizer.py` | Tables, columns, scope | Intern reads own salary | CEO salary, `OR 1=1`, join into salaries, `AVG(salary)`, literal identity: denied |
| `test_executor.py` | Runtime barriers (I5) | Allowed read returns rows | Unpermitted column denied by `set_authorizer`; slow query times out; row limit truncates |
| `test_disclosure.py` | Disclosure rule (I10, I14) | `internal` value disclosed to local model for Piotr | Sensitive value never disclosed; external model never gets sensitive; denied returns bare placeholder |
| `test_tool_loop.py` | Loop (I12) | Two `query_data` calls then answer | Endless tool calls stop at limit; mixed turn handled; extra bindings rejected |
| `test_tool_authz.py` | Client tools (I11) | Allowed `create_ticket` reaches client | Unlisted tool removed; external recipient removed; placeholder egress removed |
| `test_fill.py` | Outbound fill (I13) | Value inserted once per placeholder | Value containing `{x2}` inserted literally; unknown placeholder becomes marker |
| `test_exposure.py` | Model never sees hidden data (I7, I9) | Stub inputs contain no salary in deny mode | No sensitive value in any stub input across a two-turn conversation |
| `test_output_filter.py` | Final answer (I15) | Clean answer passes; user's own inserted salary kept | Guessed salary in model text redacted; secret in tool args redacted |
| `test_budget.py` | Limits (I18) | Request within budget passes | Request after limit blocked before any model call; judge tokens counted |
| `test_policy_reload.py` | Live config (I16, I19) | Changed threshold applies to next request | Invalid YAML keeps old policy; deleted control inherits profile; `off` on core control rejected |
| `test_models.py` | Model allowlist, digest | Allowed model used | Unlisted model blocked; digest mismatch blocked |
| `test_scan_model.py` | Model file scanner | Safe pickle fixture passes | `os.system` pickle fixture fails |
| `test_audit.py` | Logging (I17) | One record per request, including blocked | No raw secret or value in the log file |
| `test_invariants.py` | One test per invariant I1-I19 | Only `executor.py` opens `demo.db`; approved SQL runs unchanged | Any other module calling `sqlite3.connect` (besides `budget.py` for `state.db`) fails the test |
| `test_e2e.py` | Full pipeline | Piotr gets headcount and salary | Anna gets `[UNAVAILABLE]` for the CEO; blocked `send_email` reported |

Further files cover the rest of the code:

| Area | Files |
| --- | --- |
| Red team | `test_redteam_inbound.py`, `test_redteam_authorizer.py`, `test_redteam_tool_authz.py` |
| MCP tools | `test_mcp_tools.py`: calls, arguments, egress, poisoned descriptions and results of `mcp__<server>__<tool>` tools |
| Pipeline and endpoints | `test_pipeline.py`, `test_endpoints.py`, `test_streaming.py`, `test_empty_answer.py`, `test_inbound.py`, `test_smoke.py` |
| Data access | `test_scope_department.py`, `test_protected_index.py`, `test_vault.py`, `test_seed.py` |
| Models | `test_llm_client.py`, `test_external_model.py`, `test_prompts.py`, `test_stub_model.py`, `test_llm_live.py` (live) |
| Feed | `test_fetch_feed.py` |
| Reporting | `test_metrics.py`, `test_dashboard.py`, `test_demo_agent.py`, `test_bench.py` |

Current result: `1445 passed, 8 deselected`, nothing skipped (the 8 deselected are the live tests; `pytest -m live` runs them).

**Telemetry check.** `python -m tests.bench` sends a fixed prompt set and reports median
and p95 latency per pipeline step, for the slides and the performance criterion.

**Judge-friendly output.** Test names read as sentences
(`test_intern_cannot_read_ceo_salary`). The README shows the one command and an
expected summary line.
