# 12. Mapping to task requirements and criteria

Every formal requirement and expected outcome in the task PDF maps to a named
component.

## Formal requirements and expected outcomes

| Task requirement | Where it is met |
| --- | --- |
| Integrates into agent-to-model, app-to-agent, agent-to-MCP traffic | OpenAI-compatible proxy; client tools governed (sections 1, 4, 5) |
| Centralized policy engine | `policy.yaml`, live reload, effective-policy view (section 6) |
| Deterministic controls (PII, secrets, auth) | API-key auth, masker, SQL validator and authorizer, tool argument rules |
| Semantic (AI-based) controls | Judge model on user input and tool results |
| Budget and resource governance | Token, rate and cost budgets per user and role; pricing for local and external models; loop caps |
| Historical attack mitigation | Signature feed with external update, digest pinning, model file scanner (section 9) |
| Security reporting and auditing | JSONL audit, CSV export, real-time dashboard |
| Self-testing suite | pytest, allowed and blocked case per control and invariant (section 14) |
| Architecture diagram | Section 3 |
| Sample configuration with strictness levels | `policy.yaml` with strict, balanced, relaxed profiles |
| Performance telemetry | Per-step latency in every audit record; dashboard panel; `tests.bench` |
| OWASP review (task note) | Section 10 |

## Judging criteria

Weights differ between the two PDFs; both are shown.

| Criterion | Rules PDF | Task PDF | Main evidence |
| --- | --- | --- | --- |
| Robustness and quality of guardrails | 30% | 30% | Deferred binding, tool authorization, two-barrier SQL enforcement, OWASP coverage |
| Architecture and performance efficiency | 20% | 20% | One pipeline, clear trust boundary, cheapest checks first, telemetry |
| Security reporting | 20% | 20% | Audit per binding and tool decision, dashboard, export |
| Completeness of self-testing suite | 20% | 15% | One test per invariant and per edge case, stub model, one command |
| Practical implementability and scalability | 10% | 15% | Drop-in proxy, one-command start, per-request stateless pipeline |

## How judges will test, and what we support

Judges run our tests, type ad-hoc prompts and edit config live. So: the policy reloads
without restart; every block shows a readable reason in the response and on the
dashboard; the dashboard refreshes every 2 seconds; deleting or disabling a control
behaves as section 6 describes.

## Dashboard panels

Security reporting is 20%, so the dashboard is specified, not improvised:

- **Posture:** policy version and profile, every control with its mode and source (explicit,
  profile, default, off), signature feed version, model digest status.
- **Live feed:** last 50 requests with user, verdict, blocking control and reason.
- **Threats:** blocks by control and by signature category over time; top users by blocks.
- **Data access:** binding outcomes (resolved, denied, rejected, empty, error) by role and
  table; tool calls allowed and denied by tool.
- **Consumption:** tokens and cost per user against budget; requests per minute.
- **Performance:** median and p95 latency per pipeline step.
- **Export:** CSV download of the audit log for a time range.
