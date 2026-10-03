# 10. OWASP Top 10 for LLM Applications mapping

v2 covers six of the ten 2025 risks fully, three partially, and leaves one out of scope with a
stated path. The task explicitly asks teams to review OWASP; this table goes on one slide.

| OWASP risk | Coverage | Controls |
| --- | --- | --- |
| LLM01 Prompt Injection | Full | Phrase list (English and Polish), signature feed, judge model, scanning of tool results and tool definitions. Deferred binding limits the impact: injection cannot grant data access. |
| LLM02 Sensitive Information Disclosure | Full | Inbound masking, hidden-by-default query results, disclosure rule with labels, history re-masking, output filter with protected-value index. |
| LLM03 Supply Chain | Full | Model allowlist with digest pinning, model file scanner, repository and URL blocklist in the feed. |
| LLM04 Data and Model Poisoning | Partial | Digest pinning detects swapped models; database content is treated as untrusted and scanned. Training-data poisoning is out of scope. |
| LLM05 Improper Output Handling | Full | Single-pass literal fill, escaping, SQL validation before execution, tool-argument rules and output filter. |
| LLM06 Excessive Agency | Full | Tool authorization per role, argument rules, egress rule, read-only database, loop and binding limits. |
| LLM07 System Prompt Leakage | Partial | The gateway's system message holds only schema names and rules, no secrets or credentials, so leakage has little value. Echo detection is a stretch goal. |
| LLM08 Vector and Embedding Weaknesses | Out of scope | No RAG in the demo. Path: treat retrieval as another built-in tool whose results pass the same authorization, labels and disclosure rule. |
| LLM09 Misinformation | Partial | Facts about company data come from the database, not the model; guessed protected numbers are redacted. General hallucination is not addressed. |
| LLM10 Unbounded Consumption | Full | Token, request-rate and cost budgets checked before every model call, `max_tokens`, tool-loop and binding caps, SQL timeout and row limit. |
