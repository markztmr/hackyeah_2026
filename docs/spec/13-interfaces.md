# 13. Skeleton layout and interfaces

Python 3.11+, FastAPI, the `openai` SDK as the model client (works for Ollama and external
providers), sqlglot, PyYAML, SQLite, Streamlit and pytest. Policy and feed reload by
checking file modification time at the start of each request, so no file-watcher
dependency is needed. Each module has one job and a narrow interface, so four people
can work in parallel.

```text
HackYeah2026/
├── README.md                  # overview, setup, run, test
├── AI Control Layer Presentation.pdf
├── pyproject.toml
├── policy.yaml                # single source of truth
├── signatures.json            # external attack signature feed
├── .streamlit/config.toml     # shared theme for the dashboard and the demo agent
├── docs/                      # this specification (Markdown + original PDF)
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
│   │   ├── digests.py         # model digest pinning against Ollama /api/tags
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
├── dashboard/app.py           # Streamlit, auto-refresh, reads the gateway's HTTP API only
├── demo_agent/app.py          # Streamlit chat UI using the openai SDK + 2 client tools
├── scripts/model_bakeoff.py   # hour-1 model test (section 15)
└── tests/                     # section 14; tests/bench.py is the latency benchmark
```

Runtime files, not in the repository: `demo.db` (created by `db/seed.py`), `state.db`
and `logs/audit.jsonl` (created by the gateway).

The demo agent uses the stock `openai` Python SDK with
`base_url=http://localhost:8000/v1`. That one line is the integration story for the
slides.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/chat/completions` | OpenAI-compatible entry point. Header `Authorization: Bearer <user api key>`. Accepts `messages`, `tools`, `model`, `stream`. With `stream: true` the checked answer is sent as buffered SSE (`chat.completion.chunk` events, then `[DONE]`). |
| `GET /v1/models` | Allowed models, so stock clients can list them. |
| `GET /health` | Liveness, policy and feed versions, model reachability and digest status (`digests.ok`, per model `status`, `pinned`, `installed`; a fresh check). |
| `GET /metrics` | Dashboard sections computed from the audit log, one independent key each: `requests_by_verdict`, `blocks_by_control` (today, UTC), `tokens_and_cost_by_user` (today, with budget limits), `last_requests` (newest 50); `blocks_by_signature_category` (today; signature IDs in blocking `signatures` reasons mapped to the current feed's categories, unknown IDs as `unknown`), `blocks_over_time` (60 per-minute buckets `{minute, requests, blocks}`, oldest first), `blocks_by_user` (today), `binding_outcomes_by_role_and_table` (today; role -> table -> resolved/denied/rejected/empty/error), `tool_decisions_by_tool` (today; tool -> allow/deny), `latency_by_step` (today; step -> median_ms, p95_ms nearest rank, count; `total` last). New sections are new keys. |
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
  `disclosed`, `reason`, `tables`, `columns`, `rows`, `truncated`, `latency_ms`;
  `approved_sql` and `approved_for` (user ID, policy version hash), set by `authorize` on pass;
  `execute` runs only if `sql` still equals `approved_sql` and the principal and policy match (I4, I14).
- `ToolCall`: `id`, `name`, `arguments` (the JSON object, or the raw string when it was not one; step 7 denies those).
- `ToolDecision`: `tool`, `verdict`, `rule`, `reason`.
- `Decision`: `stage`, `control`, `verdict` (allow, redact, block, log), `reason`,
  `latency_ms`.
- `FilledText`: `text` plus spans marking model-written and gateway-inserted parts.
- `AuditRecord`: `request_id`, `timestamp`, `policy_version`, `feed_version`, principal
  fields, model names, decisions, binding outcomes (no values), tool decisions,
  `tool_iterations`, `disabled_controls`, tokens, cost, per-step and total latency, final
  verdict, `prompt_text` (newest user message after masking and redaction, or null when
  `audit.log_prompt_text: none`; never raw).

## Module interfaces (signatures only)

```python
authenticate(api_key: str, policy: Policy) -> Principal
check_model_and_budget(p: Principal, model: str, estimate: int, policy: Policy) -> Decision
inspect_inbound(req: ChatRequest, p: Principal, policy: Policy, cache: IssuedCache) -> tuple[SanitizedRequest, Vault, list[Decision]]
match_signatures(text: str, surface: str, feed: SignatureFeed, policy: Policy) -> Decision  # policy: mode for medium severity
scan_tool_definitions(tools: list[dict], policy: Policy, feed: SignatureFeed) -> Decision  # gateway/inbound/injection.py, step 3d
is_query_data_name(name: str) -> bool; safe_tool_label(name, index: int) -> str          # gateway/inbound/injection.py
check_injection(text: str, policy: Policy) -> Decision
judge(text: str, policy: Policy, *, models: ModelProvider | None = None) -> Decision   # a JudgeDecision (Decision + tokens); the pipeline charges tokens and records a plain Decision; failures follow semantic.on_failure
run_tool_loop(req: SanitizedRequest, p: Principal, vault: Vault, policy: Policy, *, models: ModelProvider | None = None, model: str | None = None) -> LoopResult  # block -> LoopResult.block
validate_sql(b: Binding, policy: Policy) -> Binding          # sets rejected or passes
authorize(b: Binding, p: Principal, policy: Policy) -> Binding  # sets denied or passes
execute(b: Binding, p: Principal, policy: Policy) -> Binding    # resolved / empty / error; department-scoped tables read from a TEMP copy of the user's department
department_scoped(p: Principal, policy: Policy) -> dict[str, str]   # executor: table -> department column of the role's scope-department grants; raises if a grant has none
read_column_values(columns: set[tuple[str, str]]) -> dict[tuple[str, str], list]  # executor: every value of schema columns, for the protected-value index only; same ro connection + authorizer (only those columns) + time limit; raises on unknown column or error
db_state() -> tuple[str, int, int]                                # executor: (path, mtime_ns, size) of demo.db; the index rebuilds when it changes
disclose(b: Binding, p: Principal, policy: Policy, *, trust: ModelTrust = "external") -> str  # tool result: "{x1} = <value>" only if all five disclosure conditions hold, else the bare placeholder; trust of the receiving model (rule 4); failed condition goes to b.reason
authorize_tool_call(call: ToolCall, p: Principal, bindings: dict[str, Binding], policy: Policy) -> ToolDecision
policy_approved_arguments(call: ToolCall, p: Principal, policy: Policy) -> frozenset[str]  # args whose value fully matches allow_pattern; not redacted by the output filter
fill(text: str, bindings: dict[str, Binding], vault: Vault, policy: Policy) -> FilledText
escape_value(text: str, mode: str) -> str   # output_controls.escape; also used by the executor for list cells
filter_output(f: FilledText, p: Principal, policy: Policy) -> tuple[str, Decision]   # model-written spans: secrets, PII, protected values; index unavailable -> block
protected_values(role: str, policy: Policy) -> frozenset[str]     # protected_index: normal forms of numbers from columns the role may not read or that are sensitive, >= min_digits digits
find_protected(text: str, values: frozenset[str], min_digits: int) -> list[tuple[int, int]]   # protected_index: spans of numbers matching in any formatting
normalize_number(value) -> set[str]                               # protected_index: "48,000" / "48 000" / "48.000" -> "48000"; decimals kept without trailing zeros
warm(policy: Policy) -> None                                      # protected_index: build at startup (main lifespan); failure is logged, filter then fails closed
record_issued(p: Principal, bindings: dict[str, Binding], cache: IssuedCache, *, now: float | None = None) -> None  # resolved, not disclosed: formatted value (raw + markdown-escaped) per user
remask_history(messages: list[dict], p: Principal, cache: IssuedCache, policy: Policy, *, now: float | None = None) -> tuple[list[dict], int]  # step 3c, called by inspect_inbound: assistant content + tool-call arguments, exact whole match -> markers.prior_value; returns new messages and the replacement count; policy gives enabled, ttl_minutes, marker
record_usage(p: Principal, tokens: int, model: str, policy: Policy, *, judge: bool = False) -> None  # after every model call; judge usage only if count_judge_tokens
write_audit(record: AuditRecord, policy: Policy, *, vault: Vault | None = None, bindings: Mapping[str, Binding] | None = None) -> None   # path: ACL_AUDIT_PATH or audit.path; details withheld if the guard finds a request value

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
# get_client("judge", ...) runs at temperature 0 (JUDGE_TEMPERATURE); the answer client keeps the provider default

# gateway/pipeline.py — writes exactly one audit record per call, in finally
run_pipeline(api_key, req, policy, feed, cache, *, models=None, metrics=None) -> tuple[ChatResponse, Verdict]
#   block -> assistant message, HTTP 200; AuthError -> 401; anything else -> GatewayError(request_id) -> 500

# gateway/telemetry.py
StepTimer().step(name)  # context manager; .steps dict of ms, .total_ms()
Metrics().record(verdict, steps, total_ms); Metrics().snapshot() -> dict   # GET /metrics

# gateway/audit.py
read_audit(policy, since=None, until=None) -> list[dict]; export_csv(records) -> str
audit_metrics(records, policy, *, now=None, feed=None) -> dict   # GET /metrics sections; feed maps signature IDs to categories
find_request_values(record, *, vault=None, bindings=None) -> list[str]   # field paths holding a vault original or binding value (I8)
# gateway/models.py: Vault.appears_in(text) -> bool   # for the audit guard; never returns a value
# gateway/models.py: IssuedCache.add(user_id, value, issued_at) / live_values(user_id, issued_after) -> list[str]  # drops expired; at most MAX_PER_USER per user; thread-safe; for history.py only

# gateway/inbound/masker.py — building block of inspect_inbound (steps 3a-3b)
mask_messages(messages: list[dict], policy: Policy) -> tuple[list[dict], Vault, list[Finding]]  # Finding: type, token, action
masking_decisions(findings: list[Finding]) -> list[Decision]   # block / redact / log per control, or one allow
find_sensitive(text: str) -> list[tuple[int, int, str]]          # shared with the output filter
redact_sensitive(text: str) -> str                               # [REDACTED:<type>], for audit copies
client_texts(messages: list[dict]) -> list[str]                  # every client-written field (content, name, tool_calls)

# gateway/inbound/signatures.py
parse_feed(raw: bytes) -> SignatureFeed; FeedStore(path).snapshot()/reload()/status()

# gateway/budget.py
resolve_model(model: str, policy: Policy) -> tuple[str | None, Decision]   # allowlist; None = blocked
admit_request(p: Principal, policy: Policy) -> Decision   # requests_per_minute: checked and counted once per request (step 2)
# resolve_model then applies digest pinning to the model actually used: block, control "models.digest"

# gateway/llm/digests.py — digest pinning (section 9)
check_digests(policy: Policy, *, force: bool = False) -> dict[str, ModelDigest]   # per allowed model: ok | unpinned | mismatch | missing | unverified; cached per policy version, force at startup / POST /policy/reload / GET /health, unverified retried after RETRY_S
block_reason(model: str, policy: Policy) -> str | None   # None for ok/unpinned; everything else (and any error) blocks
fetch_installed(base_url: str, timeout_s: float = 2.0) -> dict[str, str]   # GET <ollama root>/api/tags -> name: 64-hex digest
installed_digests(policy: Policy) -> dict[str, str] | None   # every Ollama base URL in the policy; None if unreachable (tests replace it)
health(policy: Policy) -> dict   # the /health "digests" section

# gateway/cli/scan_model.py — python -m gateway.cli.scan_model <path>; exit 0 allowed, 1 blocked import, 2 not scannable
scan_file(path) -> ScanReport            # pickle file or zip with .pkl members; pickletools.genops only, never unpickles
scan_bytes(data: bytes, member: str = "<file>") -> tuple[list[Import], list[str]]   # imports of back-to-back pickles, notes
is_allowed(module: str | None, name: str | None) -> bool   # ALLOWED_MODULES (torch, numpy, collections, _codecs) minus DENIED entry points

# gateway/cli/fetch_feed.py — python -m gateway.cli.fetch_feed <url> [--dest PATH] [--sha256 HEX]; exit 0 installed, 1 rejected
fetch_feed(url: str, dest=None, *, expected_sha256: str | None = None) -> SignatureFeed   # download, verify, validate, os.replace; FetchError leaves dest untouched
feed_sha256(signatures) -> str           # hex sha256 of json.dumps(signatures, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
# check_model_and_budget's estimate = prompt characters / 4 + the call's max_tokens
```

## Team split

| Person | Owns |
| --- | --- |
| 1 | `main.py`, `pipeline.py`, `policy/`, `auth.py`, `llm/`, `agency/loop.py` |
| 2 | `inbound/`, `outbound/output_filter.py`, `outbound/protected_index.py`, `cli/` |
| 3 | `binding/`, `outbound/fill.py`, `agency/tool_authz.py`, `db/` |
| 4 | `budget.py`, `audit.py`, `telemetry.py`, `dashboard/`, `demo_agent/`, stub model and test harness, benchmark, slides |
