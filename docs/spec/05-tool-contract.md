# 5. Tool contract

The model talks to the gateway only through standard tool calls. It never returns custom
JSON, so generic prompts work even if the model ignores `query_data` entirely.

## The built-in `query_data` tool

```json
{
  "type": "function",
  "function": {
    "name": "query_data",
    "description": "Run one read-only SQL query on the company database for the current user. Returns a placeholder such as {x1}. Write the placeholder in your answer exactly where the value belongs. You may not see the value.",
    "parameters": {
      "type": "object",
      "properties": {
        "sql": {"type": "string", "description": "One SELECT. Use :current_user, :current_role, :current_department for the requesting user. Never write user IDs or names as literals."},
        "purpose": {"type": "string", "description": "Short reason, shown in the audit log."},
        "expect": {"type": "string", "enum": ["scalar", "row", "list"]}
      },
      "required": ["sql", "purpose", "expect"]
    }
  }
}
```

The gateway's system message adds the schema (table and column names only), two or
three few-shot examples, and one rule for reasoning: when a comparison is needed, do it
in SQL (`CASE WHEN salary > (SELECT AVG(salary) ...) THEN 'above' ELSE 'below' END`), because the value may stay hidden. `purpose` is logged and shown on the
dashboard; it is never used for authorization.

A client tool named `query_data` is rejected: the request is blocked as a tool-name
collision.

## Placeholder rules

1. Placeholders match `{x<number>}` exactly. Any other braces are ordinary text.
2. A placeholder in the final text that matches no binding of this request becomes
   `[UNAVAILABLE]`.
3. A binding the final text never uses is logged as unused. It was already executed, which
   is why `max_bindings_per_request` bounds the number of queries.
4. The same placeholder may appear several times; it is filled with the same value each
   time.
5. Filling is a single pass. Inserted values are never scanned for further placeholders.
6. `row` renders as `column: value` pairs; `list` renders as a short Markdown table,
   truncated at `max_rows`.

## Gateway parameters

| Parameter | Filled with |
| --- | --- |
| `:current_user` | The authenticated user's ID |
| `:current_role` | The authenticated user's role |
| `:current_department` | The user's department |

Any other named or positional parameter makes the query `rejected`. Values the model
tries to supply for these parameters are ignored (I3).

## Resolution of one binding

**Validate** (`sql_validator.py`). Parse with sqlglot in the SQLite dialect. Exactly one
statement, of type `SELECT`, including `UNION` and non-recursive `WITH`. Every function
must be on `sql_controls.allowed_functions`. Only gateway parameters. Every table
and column must exist in the schema. Failure: `rejected`.

**Authorize** (`authorizer.py`). Every table referenced anywhere (joins, subqueries, CTEs,
union branches) is checked against the role:

- **Columns.** `SELECT *` is expanded from the schema and each column is checked. A
  column used anywhere counts: in `SELECT`, `WHERE`, `JOIN`, `GROUP BY`, `ORDER BY` or
  inside an aggregate.
- **Aggregates.** `AVG(salary)` is access to `salary` (decision for v2). Separate aggregate
  permissions are a stretch goal.
- **Scope `self`.** For each reference to the table, the `WHERE` or `JOIN ... ON` of the query
  level that holds it must contain `<alias>.<owner_column> = :current_user` as a **top-level
  `AND` conjunct**. `... = :current_user OR 1=1` fails, because the equality sits
  under an `OR`.
- **Scope `department`.** The same rule with `<department_column> = :current_department`. A table without a `department_column` cannot use this scope.
- **Literal identity filters.** Comparing an identity column to a literal (`WHERE employee_id = 7`, `WHERE name = 'CEO'`) is allowed only with scope `all`.

Any failure: `denied`. Unknown table, unknown column or internal error: `denied` (I6).

**Execute** (`executor.py`). The exact SQL string that passed is executed (I4) on a
connection opened as `file:demo.db?mode=ro`. It runs only for the user and policy
version it was approved for. Two runtime barriers sit on that connection:

- `set_authorizer` allows only `SQLITE_SELECT`, `SQLITE_READ` on tables and columns
  the role may read, and `SQLITE_FUNCTION` for allowlisted functions plus the functions
  SQLite uses for syntax the validator accepts (`like`, `glob`, `current_date`,
  `current_time`, `current_timestamp`). Everything else returns `SQLITE_DENY`. This
  catches any table, column, function or write the static check missed. It does not
  see rows: scope `self` is enforced only by the static authorizer, so its tests carry
  the row-level guarantee.
- **Department row barrier.** Before the query runs, each department-scoped table it
  reads is copied into a `TEMP` table of the same name holding only the rows where
  `department_column = :current_department` (bound parameter). Unqualified names
  resolve to `temp` before `main`, so the unchanged SQL string (I4) sees only the
  user's department, and `set_authorizer` allows reads of that table only from `temp`
  (a read of `main.<table>` is denied; the validator rejects qualified names anyway).
- `set_progress_handler` aborts the query after `timeout_ms`.

The executor also compares what SQLite actually read with the static result: a read of a
table or column the static checks did not record is an `error`, and the label of what
was read can only raise the binding's label.

Rows are read with `fetchmany(max_rows + 1)` so truncation is detected and logged.
Outcome: `resolved`, `empty` or `error`.

## Outcomes and markers

| Status | Meaning | Marker, strict | Marker, balanced and relaxed |
| --- | --- | --- | --- |
| `resolved` | Authorized and executed | the value | the value |
| `denied` | Table, column or scope not permitted | `[UNAVAILABLE]` | `[NOT AUTHORIZED]` |
| `rejected` | Failed validation | `[UNAVAILABLE]` | `[UNAVAILABLE]` |
| `empty` | Executed, no rows | `[UNAVAILABLE]` | `[NO DATA]` |
| `error` | Execution failed or timed out | `[UNAVAILABLE]` | `[UNAVAILABLE]` |

Strict uses one marker so that users cannot infer whether data exists. Detailed reasons go
only to the audit log.

## Disclosure rule

A `query_data` result shows the model the real value only if all of these hold. Otherwise it
shows the placeholder alone.

1. The status is `resolved`. Non-resolved bindings always return the bare placeholder, so
   the model never learns why.
2. The user's effective AI data policy is `allow`: user setting capped by the role's
   `max_ai_data_policy`.
3. The binding's label is at or below the role's `max_label_to_model`. A binding's label is
   the highest label of any column it read.
4. The model's trust is `local`, or the label is not `sensitive`.
5. The value passes the injection and signature scan (database content is untrusted too).

A disclosed value is returned as `{x1} = 12`, and the model is still asked to write the
placeholder.

## Client tool authorization

Each role lists the client tools it may use. A tool not listed is denied. Each tool may carry
argument rules:

| Rule | Example | Effect |
| --- | --- | --- |
| `allow_pattern` | `to: "^[^@]+@company\\.pl$"` | Argument must match |
| `deny_pattern` | `path: "\\.\\./"` | Argument must not match |
| `max` | `amount: 500` | Numeric argument at most this value |
| `max_label` | `internal` | Highest data label whose values may be filled into this tool's arguments |

**Egress rule.** Placeholders in client tool arguments are filled only up to the tool's
`max_label`. The default is none, so the tool call is denied rather than sent with a hidden
value or a marker. This stops the model from routing protected data out through
`send_email`.

Two consequences, because argument rules are checked before fill:

- An argument that has a rule (`allow_pattern`, `deny_pattern`, `max`) may not contain a
  placeholder at all; otherwise a database value could dodge the rule after the check.
- A value already disclosed to the model counts as that binding's egress when the model
  copies it literally into an argument (matched as a whole token, case-insensitive).

Arguments of allowed calls also pass through the output filter (secrets, PII).
