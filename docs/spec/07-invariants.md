# 7. Invariants

These 19 invariants hold for every request under every policy. Each has at least one
dedicated test (section 14).

## Trust and access

- **I1. Single data door.** Only the gateway's executor opens the database. In production,
  models and clients have no network path or credentials to it (deployment
  requirement). In the skeleton, a test asserts that only `executor.py` opens a database
  connection.
- **I2. Identity from authentication only.** The principal comes from the API key. Text in
  messages, tool results or model output never changes it.
- **I3. Gateway owns parameters.** `:current_user`, `:current_role` and
  `:current_department` are bound by the gateway. Any other parameter rejects the
  query.
- **I4. Execute what was approved.** The exact SQL string that passed validation and
  authorization is executed. Nothing is regenerated in between.
- **I5. Read-only, twice enforced.** Only single `SELECT` statements pass validation. The
  connection is opened read-only, and `set_authorizer` denies any non-read action at
  runtime.
- **I6. Deny by default.** Missing permissions, unknown tables or columns, unparsable SQL,
  unknown tools and internal errors result in denial, never access.

## Model exposure

- **I7. The model sees only sanitized messages.** User messages and tool results are
  masked, history is re-masked and tool definitions are scanned before any model call.
- **I8. The vault never leaves.** Vault contents never appear in model input, logs, or
  responses to anyone but the original user. The vault is erased when the request ends.
- **I9. Hidden values stay hidden.** A value that fails the disclosure rule never appears in
  any model input in that request. History re-masking keeps it out of later requests for
  `ttl_minutes`, by exact match (a value the user retypes in other formatting is the
  user's own disclosure).
- **I10. Disclosure respects labels.** Values above `max_label_to_model` are never
  disclosed. External models never receive `sensitive` values.

## Agency and consumption

- **I11. Tool calls are authorized before the client sees them.** A client tool call reaches the
  client only if the role lists the tool and every argument rule passes, including the egress
  rule for placeholders.
- **I12. Loops are bounded.** Each request has at most `max_tool_iterations` model calls
  in the tool loop, at most `max_bindings_per_request` queries, and `max_tokens` on
  every call.

## Output integrity

- **I13. Single-pass, literal fill.** Inserted values are escaped and never interpreted as
  placeholders, markup or instructions.
- **I14. Denial reveals nothing.** The model receives the same bare placeholder for every
  non-resolved outcome. Users see markers; the strict profile uses one marker for all of
  them.
- **I15. Output is always checked.** The output filter runs on every final answer and every
  allowed tool call's arguments.

## Governance

- **I16. One policy per request.** A request is evaluated against one policy version,
  recorded in its audit record.
- **I17. Everything is logged.** Every request produces exactly one audit record, including
  blocked and failed ones. Raw secrets and raw values never appear in logs.
- **I18. Budgets are checked before spending.** No model call (answer, loop iteration or
  judge) and no query runs once a principal's budget is exhausted.
- **I19. Guardrails are never silently disabled.** A control missing from the file inherits its
  profile value. Only `mode: off` disables it, and core controls cannot be disabled.
