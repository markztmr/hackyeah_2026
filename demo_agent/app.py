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
MODEL = "llama3.2"
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


def main() -> None:
    import streamlit as st

    st.set_page_config(page_title="Demo agent", layout="centered")
    st.title("Demo agent")
    st.caption("Stock OpenAI SDK with base_url=http://localhost:8000/v1. No security logic: the gateway decides.")
    user = st.sidebar.selectbox("User", list(USERS))
    histories: dict[str, list[dict[str, Any]]] = st.session_state.setdefault("histories", {})
    history = histories.setdefault(user, [])
    if st.sidebar.button("New conversation"):
        history.clear()

    for m in history:
        if m["role"] == "user":
            st.chat_message("user").write(m["content"])
        elif m["role"] == "assistant" and m.get("content"):
            st.chat_message("assistant").write(m["content"])
        elif m["role"] == "tool":
            st.chat_message("assistant", avatar=":material/build:").caption("Tool result: " + m["content"])

    prompt = st.chat_input("Ask as " + user)
    if not prompt:
        return
    st.chat_message("user").write(prompt)
    turn = chat_turn(make_client(USERS[user]), history, prompt)
    with st.chat_message("assistant"):
        for action in turn.actions:
            st.info(action)
        if turn.error:
            st.error(turn.error)
        elif turn.verdict == "block":
            st.error("Blocked by the gateway: " + (turn.reason or ""))
        else:
            st.write(turn.answer)
        if turn.verdict:
            st.caption("x-acl-verdict: " + turn.verdict + (" · request " + turn.request_ids[-1] if turn.request_ids else ""))


if __name__ == "__main__":
    main()
