# 11. Design analysis

The design enforces authorization outside the model and, by default, keeps sensitive
values away from it entirely. v2 adds drop-in integration and tool governance without
weakening that. The main remaining cost is that the model cannot reason over values it
never sees.

## Strengths

- **Enforcement, not advice.** The model can only propose queries and tool calls. Injection
  cannot grant access, because the model holds no credentials and no identity.
- **Drop-in.** Any OpenAI-compatible agent works by changing its base URL. Its tools keep
  working and become governed.
- **Graceful degradation.** If a small model ignores `query_data`, the request still succeeds
  as plain text. Robustness no longer depends on JSON compliance.
- **Zero exposure by default.** Safe with external models, which the task requires the
  design to support.
- **Per-value decisions.** One answer can mix permitted and denied values, each
  individually audited.
- **Clear trust boundary.** Easy to draw, explain and test.

## Risks and mitigations

| Risk | Why it matters | Mitigation |
| --- | --- | --- |
| Model cannot reason over hidden values | Comparisons and summaries need data | Push logic into SQL (`CASE`, `AVG`); disclosure where policy and label allow |
| Small model writes wrong SQL or skips the tool | Ad-hoc judge prompts fail | Native tool calling, few-shot examples, hour-1 model test; failures become markers or plain answers |
| SQL validation bypass | Parsers and regexes can be fooled | sqlglot AST checks, top-level-conjunct scope rule, SQLite `set_authorizer` at runtime, read-only connection |
| Identity spoofing inside SQL | `WHERE name = 'CEO'` instead of `:current_user` | Gateway parameters; literal identity filters need scope `all` |
| Filled values return in the next turn | Client resends history to the model | History re-masking with the issued-value cache (exact match, TTL) |
| Protected data leaves through a tool | `send_email` with a placeholder | Egress rule with per-tool `max_label` |
| Model hallucinates values into text | Bypasses placeholders | Protected-value index on model-written text only |
| Injection hidden in data or tool results | A row or a web page carries instructions | Scanned before disclosure; escaped on fill |
| Inference through markers | Different markers reveal existence | Strict profile uses one marker |
| Latency | Tool loop adds model calls | Deterministic checks first; judge only after they pass; loop cap; per-step telemetry |
| Marker sentences read oddly | "[UNAVAILABLE] PLN" | Accepted for the demo; optional `all_denied_message` |
| State in a "stateless" gateway | Budgets, rate limits and the issued-value cache are state | Stored in `state.db` and memory; Redis in production. The pipeline itself is stateless per request. |

## Resolved decisions (were open questions in v1)

| Question | Decision |
| --- | --- |
| Markers in the sentence or a single refusal sentence? | Markers in the sentence; `all_denied_message` optional. |
| Enforce row scope by rejecting or rewriting? | Reject in the MVP, with the top-level-conjunct rule and an `OR 1=1` bypass test. Rewrite (each scoped table replaced by a filtered subquery) is a stretch goal. |
| Aggregates: separate permission or column access? | Column access for now. |
| Which answering model? | `qwen2.5:3b`, chosen by the hour-1 test (section 15): it called `query_data` for every data question and used the placeholder in every answer. Judge: `qwen2.5:1.5b`. |
