# 2. Terminology

These terms are used the same way in code, logs, tests and slides. Terms new or changed
in v2 are marked (v2).

| Term | Meaning |
| --- | --- |
| Gateway | The AI Control Layer server. The only trusted component; the only holder of database credentials, the vault and the issued-value cache. |
| Client (v2) | Any app or agent calling the gateway with the OpenAI chat-completions protocol. Untrusted. The demo agent is one client. |
| Model | Any LLM the gateway calls to write answers. Local (Ollama) or external (OpenAI-compatible). Always untrusted. |
| Judge model | A small local model used only for semantic risk checks. Separate from the answering model. |
| Principal | The authenticated identity behind a request: user ID, role, department, AI data policy. Resolved from the API key, never from text. |
| Role | A named permission set in the policy (for example `intern`, `hr_manager`). |
| AI data policy | Per-user setting: may the model see query results? `deny` (default) or `allow`, capped by the role's maximum and by data labels. |
| Sanitized messages (v2) | The request's messages after inbound masking, history re-masking and checks. The only version the model sees. Replaces "sanitized prompt". |
| Mask token | Stand-in for a value found in client input, for example `[SECRET_1]` or `[EMAIL_1]`. |
| Redaction vault | Per-request, in-memory map from mask tokens and placeholders to original values. Never leaves the gateway; erased when the request ends. |
| Client tool (v2) | A tool defined by the client in the request's `tools` field. The gateway never executes it; it only authorizes calls to it. |
| Built-in tool (v2) | A tool the gateway adds to the model's tool list and executes itself. In v2 there is one: `query_data`. |
| `query_data` (v2) | Built-in tool with arguments `sql`, `purpose`, `expect`. Each call creates one binding. |
| Tool authorization (v2) | The check of a proposed client tool call against the role's allowed tools and argument rules. Outcome: `allow` or `deny`, with the rule that decided. |
| Tool loop (v2) | The gateway's repeated model calls within one request while the model keeps calling `query_data`. Bounded by `max_tool_iterations`. |
| Placeholder | A variable slot `{x1}`, `{x2}`, ... returned to the model as a `query_data` result. The model writes it into its answer. |
| Binding | One `query_data` call (placeholder, SQL, purpose, expect) plus its outcome: a value or a status. Replaces the v1 binding-map entry. |
| Resolution | Validate, authorize and execute one binding, then record its outcome. |
| Marker | Text placed in the answer for a non-resolved binding, for example `[UNAVAILABLE]`. Configurable per profile. |
| Tool result disclosure (v2) | What the model receives as a `query_data` result: the placeholder only (hidden) or the real value (disclosed). Replaces v1 "direct assembly" vs "model assembly". |
| Outbound fill (v2) | The gateway's single-pass, literal replacement of placeholders in the model's final text. Always runs, whatever the disclosure. |
| Issued-value cache (v2) | Short-lived, per-user record of hidden values the gateway inserted into answers, used for history re-masking. |
| History re-masking (v2) | Replacing previously issued hidden values in incoming conversation history so they do not reach the model on the next turn. |
| Control | One configurable check in the pipeline (PII masker, SQL validator, tool authorization, budget, and so on). |
| Mode (of a control) | What happens on a match: `block`, `redact`, `log` or `off`. |
| Profile | Preset of modes, thresholds, markers and budgets: `strict`, `balanced`, `relaxed`. |
| Signature feed | External, versioned file of known attack patterns (`signatures.json`), reloadable at runtime. |
| Audit record | One structured log entry per request describing every decision. Never contains raw secrets or values. |

Removed in v2: **response module**, **template**, **binding map**, **direct assembly**, **model
assembly** and **needs_reasoning**. The model's final message text now plays the role of the
template, and the `query_data` calls play the role of the binding map.
