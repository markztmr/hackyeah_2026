# 0. What changed in v2

v2 turns the gateway into a transparent, OpenAI-compatible proxy for any agent.
Deferred data binding stays, but as a built-in tool, `query_data`, offered to the model next
to the client's own tools. Everything else in v1 (validator, authorizer, executor, vault, direct
fill, invariants) is kept and tightened.

## Review decisions

| # | Point | Decision | Reason |
| --- | --- | --- | --- |
| 1 | Coverage: spec is a standalone app, drops client tools, irreversible tools ungoverned | Accept | Matches our own review. Breaks existing agents and the task's agent-to-MCP / app-to-agent scope. |
| 2 | One universal pipeline; deferred binding as built-in `query_data` tool; client tool authorization | Accept, amended | Sound and keeps every v1 guarantee. Amended with: history re-masking (filled values return in the next turn's history), inbound scanning of tool results and tool definitions, a loop limit, a mixed-turn rule, and an egress rule for placeholders in client tool arguments. |
| 3 | Reliability: use native tool calling, measure in hour 1 | Accept | Ollama's OpenAI-compatible endpoint supports tools for llama3.2 and qwen2.5. Generic prompts no longer depend on JSON compliance at all. |
| 4 | Explicit MVP cut | Accept, partial | Cut adopted, expressed as hour offsets from the official start (start time is disputed). Deterministic output filter moved into the MVP; tests are written alongside each module, not at the end. |
| 5 | Open questions | Partial | Markers in sentence: accept. Aggregates = column access: accept. Model by hour-1 test: accept. Reject queries without `:current_user`: accept for the MVP only with a strict top-level-conjunct check and a bypass test; rewrite moves to stretch. |
| 6 | Deadline 11:00 AM vs 11:00 PM | Accept, partial | The English competition terms we have say 11:00 PM on 4 October. We cannot see the other source, so we plan for the earlier time and confirm with organizers. |
| 7 | Streamlit real-time needs auto-refresh | Accept | Use `st.fragment(run_every=2)`; stated as a polling trade-off. |
| 8 | Glossary updates | Accept | Done in section 2. |

## Other fixes in v2

| Fix | Section |
| --- | --- |
| OWASP Top 10 for LLM Applications mapping added | 10 |
| Historical attacks: model allowlist with digest pinning, pickle opcode scanner, URL and repo blocklist, scanning model output and tool results | 9 |
| Row scope checked as a top-level `AND` conjunct per table reference; SQLite `set_authorizer` as a second barrier; `set_progress_handler` for timeouts | 5, 6 |
| SQL functions allowlisted instead of denylisted | 6 |
| Output filter checks only model-written text for guessed values; gateway-inserted values are authorized by construction | 4 |
| `owner_column`, `department_column` and `identity_columns` per table; the undefined "others" permission removed | 6 |
| Removed or missing controls fall back to the profile default and are shown on the dashboard; `mode: off` disables explicitly | 6 |
| Strict profile uses one marker for every non-resolved outcome; I12 restated | 6, 7 |
| Missing keys added: `semantic.on_failure`, `echo_own_input`, `scope_enforcement`, `aggregates` | 6 |
| Demo users cover both assembly paths (an `internal` value can reach the model) | 6 |
| Budgets persisted in SQLite; "stateless" claim corrected; `max_tokens` on every call | 4, 11 |
| Judge prompt hardened; `llama-guard3:1b` added as a candidate | 4 |
| Typo `[NOTAUTHORIZED]` fixed; I1 worded as a production requirement | 4, 7 |
