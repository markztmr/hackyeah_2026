# 13. Skeleton layout and interfaces

Python 3.11+, FastAPI, the `openai` SDK as the model client (works for Ollama and external
providers), sqlglot, PyYAML, SQLite, Streamlit and pytest. Policy and feed reload by
checking file modification time at the start of each request, so no file-watcher
dependency is needed. Each module has one job and a narrow interface, so four people
can work in parallel.

```text
HackYeah2026/
├── CLAUDE.md                  # rules for Claude Code sessions
├── README.md                  # setup, run, test in a few commands
├── pyproject.toml
├── policy.yaml                # single source of truth
├── signatures.json            # external attack signature feed
├── gateway/
│   ├── main.py                # FastAPI app and endpoints only
│   ├── pipeline.py            # the 10 steps, in order
│   ├── models.py              # shared data types
│   ├── auth.py                # API key -> Principal
│   ├── budget.py              # check and record usage (state.db)
│   ├── audit.py               # audit records, JSONL, CSV export
│   ├── telemetry.py           # per-step timers
│   ├── policy/
│   │   ├── loader.py          # load, validate, merge profile, reload, hash
│   │   └── profiles.py        # strict / balanced / relaxed presets
│   ├── inbound/
│   │   ├── masker.py          # secrets + PII -> mask tokens, vault
│   │   ├── history.py         # history re-masking, issued-value cache
│   │   ├── injection.py       # phrase list (EN + PL)
│   │   ├── signatures.py      # feed loading and matching per surface
│   │   └── judge.py           # semantic check via judge model
│   ├── llm/
│   │   ├── client.py          # OpenAI-compatible adapter + stub
│   │   └── prompts.py         # system message, few-shot, query_data schema
│   ├── agency/
│   │   ├── loop.py            # tool loop, mixed-turn rule, limits
│   │   └── tool_authz.py      # client tool rules, argument rules, egress
│   ├── binding/
│   │   ├── sql_validator.py   # parse, SELECT only, functions, params
│   │   ├── authorizer.py      # tables, columns, scope, literal identity
│   │   ├── executor.py        # ro connection, set_authorizer, limits
│   │   └── disclosure.py      # placeholder or value for the model
│   ├── outbound/
│   │   ├── fill.py            # single-pass literal fill, spans
│   │   ├── output_filter.py   # final checks on text and tool args
│   │   └── protected_index.py # values the user may not see
│   └── cli/
│       ├── fetch_feed.py      # download, verify, replace signatures.json
│       └── scan_model.py      # pickle opcode scanner
├── db/
│   ├── schema.sql             # products, employees, salaries
│   └── seed.py                # fake demo data
├── dashboard/app.py           # Streamlit, auto-refresh
├── demo_agent/app.py          # chat UI using the openai SDK + 2 client tools
└── tests/                     # section 14
```

The demo agent uses the stock `openai` Python SDK with
`base_url=http://localhost:8000/v1`. That one line is the integration story for the
slides.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/chat/completions` | OpenAI-compatible entry point. Header `Authorization: Bearer <user api key>`. Accepts `messages`, `tools`, `model`. |
| `GET /v1/models` | Allowed models, so stock clients can list them. |
| `GET /health` | Liveness, policy and feed versions, model reachability and digest status. |
| `GET /metrics` | Counters and latency summaries for the dashboard. |
| `GET /policy/effective` | Every control with its value and source. |
| `POST /policy/reload` | Manual reload of policy and feed; returns success or the validation error. |
| `GET /audit/export?format=csv` | Audit export for security teams. |

Blocked requests return HTTP 200 with an assistant message stating the reason and an
`x-acl-verdict` header, so stock clients show the reason instead of crashing.
Authentication failures return 401.

## Core data types (`gateway/models.py`)

- `Principal`: `user_id`, `role`, `department`, `ai_data_policy` (effective).
- `Vault`: mask tokens and placeholders to values. Held in memory, never serialized.
- `SanitizedRequest`: `messages`, `tools`, `findings` (type and token per match).
- `Binding`: `name`, `sql`, `purpose`, `expect`; after resolution `status`, `value`, `label`,
  `disclosed`, `reason`, `tables`, `columns`, `rows`, `truncated`, `latency_ms`.
- `ToolDecision`: `tool`, `verdict`, `rule`, `reason`.
- `Decision`: `stage`, `control`, `verdict` (allow, redact, block, log), `reason`,
  `latency_ms`.
- `FilledText`: `text` plus spans marking model-written and gateway-inserted parts.
- `AuditRecord`: `request_id`, `timestamp`, `policy_version`, `feed_version`, principal
  fields, model names, decisions, binding outcomes (no values), tool decisions,
  `tool_iterations`, `disabled_controls`, tokens, cost, per-step and total latency, final
  verdict.

## Module interfaces (signatures only)

```python
authenticate(api_key: str, policy: Policy) -> Principal
check_model_and_budget(p: Principal, model: str, estimate: int, policy: Policy) -> Decision
inspect_inbound(req: ChatRequest, p: Principal, policy: Policy, cache: IssuedCache) -> tuple[SanitizedRequest, Vault, list[Decision]]
match_signatures(text: str, surface: str, feed: SignatureFeed) -> Decision
check_injection(text: str, policy: Policy) -> Decision
judge(text: str, policy: Policy, *, models: ModelProvider | None = None) -> Decision
run_tool_loop(req: SanitizedRequest, p: Principal, vault: Vault, policy: Policy, *, models: ModelProvider | None = None, model: str | None = None) -> LoopResult  # block -> LoopResult.block
validate_sql(b: Binding, policy: Policy) -> Binding          # sets rejected or passes
authorize(b: Binding, p: Principal, policy: Policy) -> Binding  # sets denied or passes
execute(b: Binding, p: Principal, policy: Policy) -> Binding    # resolved / empty / error
disclose(b: Binding, p: Principal, policy: Policy, *, trust: ModelTrust) -> str  # tool result; trust of the receiving model (rule 4)
authorize_tool_call(call: ToolCall, p: Principal, bindings: dict[str, Binding], policy: Policy) -> ToolDecision
fill(text: str, bindings: dict[str, Binding], vault: Vault, policy: Policy) -> FilledText
filter_output(f: FilledText, p: Principal, policy: Policy) -> tuple[str, Decision]
record_issued(p: Principal, bindings: dict[str, Binding], cache: IssuedCache) -> None
record_usage(p: Principal, tokens: int, model: str, policy: Policy) -> None
write_audit(record: AuditRecord, policy: Policy) -> None   # path: ACL_AUDIT_PATH or audit.path

# gateway/policy/loader.py
parse_policy(raw: bytes) -> Policy                  # validate + merge; raises PolicyError
load_policy(path: str | PathLike) -> Policy
setting(policy: Policy, path: str) -> Any           # dotted path, e.g. "sql_controls.max_rows"
effective_policy(policy: Policy) -> dict            # every control with value and source
PolicyStore(path).snapshot() -> Policy              # once per request; reloads if mtime changed
PolicyStore(path).reload() -> dict                  # manual reload; returns status()
PolicyStore(path).status() -> dict                  # version, profile, last error (for /health)

# gateway/llm/client.py — the stub and the real client implement ModelClient.complete
get_client(purpose: Purpose, policy: Policy) -> ModelClient   # default ModelProvider
call_model(client: ModelClient, purpose: Purpose, policy: Policy, messages, tools=None, *, model=None) -> ModelReply
# models=None means default_provider(); run_pipeline(..., *, models=...) passes it to judge and run_tool_loop

# gateway/pipeline.py — writes exactly one audit record per call, in finally
run_pipeline(api_key, req, policy, feed, cache, *, models=None, metrics=None) -> tuple[ChatResponse, Verdict]
#   block -> assistant message, HTTP 200; AuthError -> 401; anything else -> GatewayError(request_id) -> 500

# gateway/telemetry.py
StepTimer().step(name)  # context manager; .steps dict of ms, .total_ms()
Metrics().record(verdict, steps, total_ms); Metrics().snapshot() -> dict   # GET /metrics

# gateway/audit.py
read_audit(policy, since=None, until=None) -> list[dict]; export_csv(records) -> str

# gateway/inbound/signatures.py
parse_feed(raw: bytes) -> SignatureFeed; FeedStore(path).snapshot()/reload()/status()

# gateway/budget.py
resolve_model(model: str, policy: Policy) -> tuple[str | None, Decision]   # allowlist; None = blocked
```

## Team split

| Person | Owns |
| --- | --- |
| 1 | `main.py`, `pipeline.py`, `policy/`, `auth.py`, `llm/`, `agency/loop.py` |
| 2 | `inbound/`, `outbound/output_filter.py`, `outbound/protected_index.py`, `cli/` |
| 3 | `binding/`, `outbound/fill.py`, `agency/tool_authz.py`, `db/` |
| 4 | `budget.py`, `audit.py`, `telemetry.py`, `dashboard/`, `demo_agent/`, stub model and test harness, benchmark, slides |
