# 1. Overview and goals

The AI Control Layer is a gateway that sits between any AI client (an agent, an app, an
MCP host) and an LLM. It speaks the OpenAI chat-completions protocol on both sides, so
an existing agent only changes its base URL and API key. It is the only component allowed
to touch sensitive data.

The gateway governs three kinds of traffic in one pipeline:

- **Text** in both directions: prompts, conversation history and answers are masked,
  checked and filtered.
- **Client tools**: tool calls the model proposes for the client's own tools (`send_email`,
  `create_ticket`, MCP tools) are authorized per role and argument before the client
  ever sees them.
- **Data access**: the gateway adds one built-in tool, `query_data`. The model proposes
  SQL; the gateway validates, authorizes and executes it for the authenticated user, and
  by default returns only a placeholder (`{x1}`) to the model. The gateway fills the
  placeholder in the final answer.

This last mechanism is **deferred data binding**: the model does the language work, the
gateway does the data work, and sensitive values reach the model only when the user's
policy allows it.

## Goals

- **G1. No unauthorized data access.** A user receives only database values their role
  permits, whatever the prompt or model says.
- **G2. Minimal model exposure.** Sensitive values reach the model only if the user's AI
  data policy and the data label allow it. By default the model never sees them, in this
  turn or later turns.
- **G3. Clean inputs.** Secrets and PII in prompts, history and tool results are masked
  before the model sees them, and stay recoverable inside the gateway.
- **G4. Governed agency.** Every client tool call is checked against the policy before it
  reaches the client. Irreversible tools can be denied or constrained by argument rules.
- **G5. Drop-in and provider-agnostic.** Any OpenAI-compatible client works unchanged.
  Local (Ollama) and external models use one adapter; external models are treated as
  untrusted.
- **G6. Governed and observable.** One policy file, reloaded live, drives every decision.
  One audit record per request feeds a real-time dashboard.
- **G7. Provable.** Every control has automated allowed and blocked tests.

**Scope for HackYeah 2026.** "AI Control Layer" open task (Proidea, Tauron Arena Krakow, 3–4 October 2026). Everything runs locally with free tools; Ollama is the default backend.
The demo agent and model are not graded; the gateway, policy, dashboard and test suite
are.

**Out of scope.** Training or fine-tuning, production identity (SSO), multi-node deployment,
streaming responses, RAG and vector stores. These are described as scalability paths,
not built.
