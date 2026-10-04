# 6. Policy model

One file, `policy.yaml`, is the single source of truth for every control. The gateway
watches it and reloads on change. An invalid file is rejected, the last valid policy stays
active, and the rejection is shown on the dashboard and in the `POST /policy/reload`
response.

## Precedence and removed controls

Each setting resolves as: explicit value in the file, else the profile preset, else the strict
default. `GET /policy/effective` and the dashboard show every control with its source:
`explicit`, `profile` or `default`.

- **A control deleted from the file** falls back to its profile value. It is not silently disabled,
  because a typo must never turn off a guardrail. The dashboard marks it `inherited from profile`.
- **`mode: off`** disables a control explicitly. The dashboard shows it in red and every audit
  record lists it under `disabled_controls`.
- **Core controls cannot be disabled**: authentication, SQL validation, authorization, the
  read-only executor, single-pass fill and audit. Setting `off` on them is a validation error.

This gives judges predictable results: deleting the `injection` block in `relaxed` gives
`log`; setting `injection: {mode: off}` really turns it off.

## Profiles

| Setting | strict | balanced | relaxed |
| --- | --- | --- | --- |
| `semantic.block_threshold` | 0.70 | 0.80 | 0.90 |
| `semantic.on_failure` | block | block | allow_and_flag |
| `secrets.mode` | block | redact | redact |
| `pii.mode` | redact | redact | log |
| `injection.mode` | block | block | log |
| Markers | one marker for all | distinct | distinct |
| `select_star` | reject | expand | expand |
| `echo_own_input` | false | true | true |
| `max_tool_iterations` | 3 | 4 | 6 |
| Default `tokens_per_day` | 20,000 | 50,000 | 200,000 |

## Principals, roles and data

- **Users** have an API key (demo-grade, plain text in the file), a role, a department and an
  AI data policy. The effective AI data policy is the user's setting capped by the role's
  `max_ai_data_policy`.
- **Tables** carry a label, an `owner_column` (for scope `self`), an optional
  `department_column` (for scope `department`) and `identity_columns` (for the literal-filter rule). Column labels override the table label.
- **Roles** grant tables with a scope (`self`, `department`, `all`) and an optional column list.
  Not listed means no access. Roles also list client tools with argument rules, plus
  `max_ai_data_policy` and `max_label_to_model`.

## Live reload contract

A policy change applies to the next request, never to one in flight. Each audit record
stores the version hash of the policy it was evaluated against. `signatures.json` reloads
the same way, with its own version.

## Complete example

```yaml
version: 2
profile: strict                 # strict | balanced | relaxed

models:
  answer:
    provider: ollama            # ollama | openai_compatible
    base_url: http://localhost:11434/v1
    name: "qwen2.5:3b"          # final choice from the hour-1 test
    trust: local                # local | external
    max_tokens: 512
    timeout_s: 30                # seconds per model call
  judge:
    provider: ollama
    base_url: http://localhost:11434/v1
    name: "qwen2.5:1.5b"
    max_tokens: 32
    timeout_s: 10
  allowed:                      # digest from Ollama /api/tags; mismatch = model blocked
    - { name: "qwen2.5:3b",   digest: "sha256:<pin>" }
    - { name: "qwen2.5:1.5b", digest: "sha256:<pin>" }
  on_unlisted: block            # block | substitute (use models.answer)

users:
  anna:  { api_key: demo-anna,  role: intern,     department: sales, ai_data_policy: deny }
  marek: { api_key: demo-marek, role: sales_lead, department: sales, ai_data_policy: allow }
  piotr: { api_key: demo-piotr, role: hr_manager, department: hr,    ai_data_policy: allow }

data:
  tables:
    products:
      label: public
    employees:
      label: internal
      owner_column: id
      department_column: department
      identity_columns: [id, name, email]
      columns: { email: sensitive }
    salaries:
      label: sensitive
      owner_column: employee_id
      identity_columns: [employee_id]

roles:
  intern:
    max_ai_data_policy: deny
    max_label_to_model: public
    tables:
      products:  { scope: all }
      employees: { scope: self, columns: [id, name, department] }
      salaries:  { scope: self }
    tools:
      send_email:
        args: { to: { allow_pattern: "^[^@]+@company\\.pl$" } }
  sales_lead:
    max_ai_data_policy: allow
    max_label_to_model: internal
    tables:
      products:  { scope: all }
      employees: { scope: department, columns: [id, name, department] }
      salaries:  { scope: self }
    tools:
      send_email:
        args: { to: { allow_pattern: "^[^@]+@company\\.pl$" } }
      create_ticket: {}
  hr_manager:
    max_ai_data_policy: allow
    max_label_to_model: internal  # salaries are sensitive: never sent to the model
    tables:
      products:  { scope: all }
      employees: { scope: all }
      salaries:  { scope: all }
    tools:
      send_email:
        args: { to: { allow_pattern: "^[^@]+@company\\.pl$" } }
        max_label: internal       # may email internal values, never salaries
      create_ticket: {}
      # delete_employee, transfer_funds: not listed, so denied

prompt_controls:
  secrets:          { mode: block }     # API keys, passwords, private keys, tokens
  pii:              { mode: redact, types: [email, phone, card, pesel, iban] }
  injection:        { mode: block }     # phrase list, English and Polish
  signatures:       { mode: block, feed: signatures.json }
  semantic:         { enabled: true, block_threshold: 0.70, on_failure: block }
  tool_definitions: { mode: block }     # scan client tool names and descriptions
  history_remask:   { enabled: true, ttl_minutes: 60 }

sql_controls:
  allow_statements: [SELECT]
  allowed_functions: [count, sum, avg, min, max, round, abs, coalesce, ifnull,
                      lower, upper, length, date, strftime]
  select_star: reject             # reject | expand
  scope_enforcement: reject       # reject | rewrite (stretch)
  aggregates: column_access       # column_access | separate (stretch)
  recursive_cte: reject
  max_rows: 50
  timeout_ms: 500
  max_bindings_per_request: 10

tool_controls:
  max_tool_iterations: 3
  unknown_tool: deny
  placeholder_egress: deny        # applies when a tool has no max_label

output_controls:
  mode: redact                    # redact | block
  echo_own_input: false
  protected_values: { enabled: true, min_digits: 4 }
  escape: markdown                # markdown | none

markers:                          # strict: one marker for every non-resolved outcome
  denied: "[UNAVAILABLE]"
  rejected: "[UNAVAILABLE]"
  empty: "[UNAVAILABLE]"
  error: "[UNAVAILABLE]"
  prior_value: "[PRIOR_VALUE]"
  all_denied_message: null        # optional single refusal sentence

budgets:
  default:    { tokens_per_day: 20000, requests_per_minute: 10, cost_per_day_usd: 0.50 }
  hr_manager: { tokens_per_day: 200000 }
  count_judge_tokens: true
  store: state.db

pricing_per_1k_tokens:            # notional for local compute; real for external
  "qwen2.5:3b": 0.0002
  "qwen2.5:1.5b": 0.0001
  gpt-4o-mini: 0.0006

audit:
  path: logs/audit.jsonl
  log_prompt_text: masked         # masked | none (never raw)
  hash_chain: false               # stretch: tamper-evident log

dashboard:
  refresh_seconds: 2
```

**Reserved values.** The validator accepts `sql_controls.scope_enforcement: rewrite`,
`sql_controls.aggregates: separate` and `audit.hash_chain: true`, but these stretch
features are not built: the gateway always rejects out-of-scope queries, treats
aggregates as column access and writes a plain JSONL log.

The three demo users cover every path: Anna sees only hidden values and self scope;
Marek demonstrates department scope and disclosure of `internal` values; Piotr
demonstrates mixed disclosure (headcounts to the model, salaries filled by the gateway)
and a tool with `max_label`.
