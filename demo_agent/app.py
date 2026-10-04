"""Chat UI using the openai SDK + 2 client tools. Spec section 4 'Worked examples', section 13. Owner: Person 4.

    streamlit run demo_agent/app.py         # needs the gateway on port 8000

An ordinary agent, as any company would write one: the stock ``openai`` SDK, a
conversation history it resends every turn, and two local tools (``send_email``,
``create_ticket``) that are fakes and only print what they would do. The only change
needed to put it behind the AI Control Layer is ``base_url`` in ``make_client``.

There is no security logic here on purpose: the agent is untrusted by design, and every
control lives in the gateway. The agent only shows what the gateway decided
(``x-acl-verdict`` and the block reason).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
from openai import APIConnectionError, APIStatusError, OpenAI

USERS = {"anna": "demo-anna", "marek": "demo-marek", "piotr": "demo-piotr"}
MODEL = "qwen2.5:3b"  # the gateway's answer model (policy.yaml models.answer)
MAX_TOOL_ROUNDS = 5  # an agent loop is bounded too
BLOCK_PREFIX = "Request blocked: "

TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient address"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_ticket",
            "description": "Create a support ticket.",
            "parameters": {
                "type": "object",
                "properties": {"title": {"type": "string"}, "body": {"type": "string"}},
                "required": ["title", "body"],
            },
        },
    },
]


def make_client(api_key: str, http_client: httpx.Client | None = None) -> OpenAI:
    """The whole integration: point the stock SDK at the gateway and use the user's key."""
    return OpenAI(base_url="http://localhost:8000/v1", api_key=api_key, http_client=http_client)


# ---------------------------------------------------------------------------
# Local tools (fakes)
# ---------------------------------------------------------------------------


def _send_email(to: str, subject: str, body: str) -> tuple[str, str]:
    return f"would send email to {to}: {subject!r} ({body})", f"Email to {to} queued: {subject}"


def _create_ticket(title: str, body: str) -> tuple[str, str]:
    return f"would create ticket {title!r} ({body})", f"Ticket created: {title}"


_FAKES = {
    "send_email": (_send_email, ("to", "subject", "body")),
    "create_ticket": (_create_ticket, ("title", "body")),
}


def execute(name: str, arguments: str) -> tuple[str | None, str]:
    """Run a fake tool: print what would happen. Returns (action or None on error, tool result for the model)."""
    if name not in _FAKES:
        return None, f"Error: unknown tool {name}."
    fake, params = _FAKES[name]
    try:
        args = json.loads(arguments or "{}")
        action, result = fake(*(str(args.get(k, "")) for k in params))
    except (ValueError, AttributeError):
        return None, f"Error: arguments of {name} are not valid JSON."
    print(name + ": " + action)
    return action, result


def run_tool(name: str, arguments: str) -> str:
    """The tool result for the model (the fake prints what it would do)."""
    return execute(name, arguments)[1]


# ---------------------------------------------------------------------------
# One user turn: request, local tool rounds, final answer
# ---------------------------------------------------------------------------


@dataclass
class Turn:
    answer: str = ""
    verdict: str | None = None  # x-acl-verdict of the last response
    reason: str | None = None  # the gateway's block reason, when blocked
    request_ids: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)  # what the fake tools would have done
    error: str | None = None


def chat_turn(client: OpenAI, history: list[dict[str, Any]], user_text: str) -> Turn:
    """Send the history plus ``user_text``; run requested tools locally and send their results back.

    ``history`` is updated in place like a real agent's; a turn that fails with an HTTP
    error is rolled back so it can simply be retried.
    """
    turn = Turn()
    start = len(history)
    history.append({"role": "user", "content": user_text})
    try:
        for _ in range(MAX_TOOL_ROUNDS + 1):
            raw = client.chat.completions.with_raw_response.create(model=MODEL, messages=history, tools=TOOLS)
            turn.verdict = raw.headers.get("x-acl-verdict")
            if raw.headers.get("x-acl-request-id"):
                turn.request_ids.append(raw.headers["x-acl-request-id"])
            message = raw.parse().choices[0].message
            content = message.content or ""
            calls = message.tool_calls or []
            entry: dict[str, Any] = {"role": "assistant", "content": content}
            if calls:
                entry["tool_calls"] = [
                    {"id": c.id, "type": "function", "function": {"name": c.function.name, "arguments": c.function.arguments}}
                    for c in calls
                ]
            history.append(entry)
            if not calls:
                turn.answer = content
                if turn.verdict == "block":
                    turn.reason = content.removeprefix(BLOCK_PREFIX)
                return turn
            if len(turn.actions) >= MAX_TOOL_ROUNDS:
                break
            for c in calls:
                action, result = execute(c.function.name, c.function.arguments)
                if action is not None:
                    turn.actions.append(c.function.name + ": " + action)
                history.append({"role": "tool", "tool_call_id": c.id, "content": result})
        turn.error = f"Stopped after {MAX_TOOL_ROUNDS} tool rounds."
        return turn
    except APIStatusError as e:
        del history[start:]
        rid = e.response.headers.get("x-acl-request-id")
        turn.error = f"Gateway answered HTTP {e.status_code}" + (f" (request {rid})." if rid else ".")
        return turn
    except APIConnectionError:
        del history[start:]
        turn.error = "Gateway unreachable at http://localhost:8000. Start it with `uvicorn gateway.main:app`."
        return turn


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------


ROLES = {"anna": "Intern · sales", "marek": "Sales lead · sales", "piotr": "HR manager · HR"}  # labels only
SUGGESTIONS = {  # the worked examples of spec section 4
    "My salary and the CEO's": "What is my salary and what does the CEO earn?",
    "Sales headcount and pay": "How many people work in sales, and what is their average salary?",
    "Email an outside address": "Email the Q3 numbers to partner@example.com.",
    "Tell me a joke": "Tell me a joke.",
}
CSS = """
<style>
header[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 2.2rem; max-width: 820px; }
.agent-hero { padding: 1.3rem 1.6rem; border-radius: 1.1rem; margin-bottom: 1.2rem; color: #f8fafc;
  background: linear-gradient(120deg, #0f172a 0%, #1e293b 60%, #334155 100%);
  box-shadow: 0 10px 30px -12px rgba(15, 23, 42, .45); }
.agent-hero h1 { margin: 0; padding: 0; font-size: 1.7rem; font-weight: 800; letter-spacing: -.02em; color: #f8fafc; }
.agent-hero p { margin: .25rem 0 0; color: #cbd5e1; font-size: .95rem; }
.agent-hero code { color: #e2e8f0; background: rgba(148, 163, 184, .2); padding: .1rem .4rem; border-radius: .4rem; }
[data-testid="stChatMessage"] { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 1rem;
  padding: .9rem 1.1rem; box-shadow: 0 1px 2px rgba(15, 23, 42, .04); }
[data-testid="stSidebar"] h2 { font-size: 1.05rem; letter-spacing: .02em; }
.agent-role { color: #94a3b8; font-size: .9rem; margin-top: -.4rem; }
</style>
"""


def _show(meta: dict[str, Any] | None, content: str) -> None:
    """One assistant answer, with the gateway's verdict as a badge."""
    import streamlit as st

    verdict = (meta or {}).get("verdict")
    if verdict == "block":
        st.error("Blocked by the gateway: " + content.removeprefix(BLOCK_PREFIX), icon=":material/block:")
    else:
        st.markdown(content)
    if verdict:
        color = {"block": "red", "allow": "green"}.get(verdict, "orange")
        rid = (meta or {}).get("request_id")
        st.badge("x-acl-verdict: " + verdict, color=color, icon=":material/shield:")
        if rid:
            st.caption("request " + rid)


def main() -> None:
    import streamlit as st

    st.set_page_config(page_title="Demo agent", page_icon=":material/smart_toy:", layout="centered")
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown(
        '<div class="agent-hero"><h1>Demo agent</h1><p>Stock OpenAI SDK with '
        "<code>base_url=http://localhost:8000/v1</code>. No security logic here: the gateway decides.</p></div>",
        unsafe_allow_html=True)

    st.sidebar.header("Signed in as")
    user = st.sidebar.selectbox("User", list(USERS), label_visibility="collapsed")
    st.sidebar.markdown(f'<div class="agent-role">{ROLES[user]} · key <code>{USERS[user]}</code></div>',
                        unsafe_allow_html=True)
    histories: dict[str, list[dict[str, Any]]] = st.session_state.setdefault("histories", {})
    metas: dict[str, dict[int, dict[str, Any]]] = st.session_state.setdefault("metas", {})
    history, meta = histories.setdefault(user, []), metas.setdefault(user, {})
    st.sidebar.divider()
    if st.sidebar.button("New conversation", icon=":material/add_comment:", use_container_width=True):
        history.clear()
        meta.clear()
    st.sidebar.caption("Tools offered to the model: send_email, create_ticket (fakes that only print).")

    for i, m in enumerate(history):
        if m["role"] == "user":
            st.chat_message("user").markdown(m["content"])
        elif m["role"] == "assistant" and m.get("content"):
            with st.chat_message("assistant"):
                _show(meta.get(i), m["content"])
        elif m["role"] == "tool":
            st.chat_message("assistant", avatar=":material/build:").caption("Tool result: " + m["content"])

    prompt = st.chat_input("Ask as " + user)
    if not history and not prompt:
        st.caption("Try one of the worked examples")
        for column, (label, text) in zip(st.columns(2), list(SUGGESTIONS.items())[:2]):
            if column.button(label, use_container_width=True):
                prompt = text
        for column, (label, text) in zip(st.columns(2), list(SUGGESTIONS.items())[2:]):
            if column.button(label, use_container_width=True):
                prompt = text
    if not prompt:
        return
    st.chat_message("user").markdown(prompt)
    with st.chat_message("assistant"), st.spinner("Waiting for the gateway..."):
        turn = chat_turn(make_client(USERS[user]), history, prompt)
    if turn.error:
        with st.chat_message("assistant"):
            st.error(turn.error, icon=":material/cloud_off:")
        return
    if history and history[-1]["role"] == "assistant":
        meta[len(history) - 1] = {"verdict": turn.verdict,
                                  "request_id": turn.request_ids[-1] if turn.request_ids else None}
    st.rerun()


if __name__ == "__main__":
    main()
