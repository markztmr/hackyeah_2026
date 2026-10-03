"""Shared data types (spec section 13, "Core data types"). Owner: Person 1.

Internal types are dataclasses. Pydantic v2 is used only for HTTP request and
response bodies (ChatRequest, ChatResponse).

Raw values (vault entries, binding values, filled text, tool arguments) are
excluded from every ``repr`` so they cannot leak into logs or exceptions (I8).
"""
from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, NoReturn

from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------
# Vocabularies (spec sections 4, 5, 6)
# ---------------------------------------------------------------------------

Verdict = Literal["allow", "redact", "block", "log"]
ToolVerdict = Literal["allow", "deny"]
BindingStatus = Literal["resolved", "denied", "rejected", "empty", "error"]
Expect = Literal["scalar", "row", "list"]
Label = Literal["public", "internal", "sensitive"]
AiDataPolicy = Literal["allow", "deny"]
Profile = Literal["strict", "balanced", "relaxed"]
ModelTrust = Literal["local", "external"]
ControlSource = Literal["explicit", "profile", "default"]
SpanSource = Literal["model", "gateway"]


# ---------------------------------------------------------------------------
# Sealed containers: hold raw values, never serialize (I8)
# ---------------------------------------------------------------------------


class _Sealed:
    """Base for containers of raw values. Cannot be pickled, copied or JSON-encoded.

    ``__slots__`` removes ``__dict__``, so ``vars()`` and FastAPI's
    ``jsonable_encoder`` fail instead of dumping the contents. ``json.dumps``
    already rejects unknown objects. ``__iter__`` is disabled so ``dict(obj)``
    and ``list(obj)`` cannot enumerate values.
    """

    __slots__ = ()

    def _refuse(self, *_: Any, **__: Any) -> NoReturn:
        raise TypeError(f"{type(self).__name__} must never be serialized or copied")

    __reduce__ = _refuse
    __reduce_ex__ = _refuse
    __getstate__ = _refuse
    __copy__ = _refuse
    __deepcopy__ = _refuse

    def __iter__(self) -> NoReturn:
        raise TypeError(f"{type(self).__name__} is not iterable")


class Vault(_Sealed):
    """Mask tokens and placeholders -> raw values. In memory only, one per request.

    Spec section 13; invariants I7, I8.
    """

    __slots__ = ("_masks", "_placeholders")

    def __init__(self) -> None:
        self._masks: dict[str, str] = {}
        self._placeholders: dict[str, str] = {}

    def add_mask(self, token: str, value: str) -> None:
        """Store the original behind a mask token such as ``[EMAIL_1]``."""
        self._masks[token] = value

    def mask(self, token: str) -> str | None:
        """The original behind a mask token, or None. Only for outbound restore (echo_own_input)."""
        return self._masks.get(token)

    @property
    def mask_count(self) -> int:
        return len(self._masks)

    def appears_in(self, text: str) -> bool:
        """Whether any original in the vault occurs in ``text`` (case-insensitive).

        For the audit guard: it answers yes or no and never hands a value out.
        """
        folded = text.casefold()
        return any(v.strip() and v.strip().casefold() in folded
                   for v in (*self._masks.values(), *self._placeholders.values()))

    def __repr__(self) -> str:
        return f"Vault(mask_tokens={len(self._masks)}, placeholders={len(self._placeholders)})"

    __str__ = __repr__


class IssuedCache(_Sealed):
    """Hidden values already shown to each user, for history re-masking.

    Spec section 4 step 3c and step 10. Lives across requests in process memory.
    """

    __slots__ = ("_entries", "_lock")
    MAX_PER_USER = 1000  # oldest entries are dropped beyond this, so memory stays bounded

    def __init__(self) -> None:
        # user_id -> {value: issued_at_epoch_seconds}; insertion order is age order
        self._entries: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()  # requests run in a thread pool

    def add(self, user_id: str, value: str, issued_at: float) -> None:
        """Remember a value issued to ``user_id``; issuing it again refreshes its age."""
        if not value:
            return
        with self._lock:
            entries = self._entries.setdefault(user_id, {})
            entries.pop(value, None)
            entries[value] = issued_at
            while len(entries) > self.MAX_PER_USER:
                del entries[next(iter(entries))]

    def live_values(self, user_id: str, issued_after: float) -> list[str]:
        """Values issued to ``user_id`` after ``issued_after``; older ones are dropped. For re-masking only."""
        with self._lock:
            entries = self._entries.get(user_id)
            if not entries:
                return []
            for value in [v for v, t in entries.items() if t <= issued_after]:
                del entries[value]
            if not entries:
                del self._entries[user_id]
                return []
            return list(entries)

    def __repr__(self) -> str:
        return f"IssuedCache(users={len(self._entries)}, values={sum(len(v) for v in self._entries.values())})"

    __str__ = __repr__


# ---------------------------------------------------------------------------
# Identity and policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is asking. Built only from the API key (I2). Spec sections 4 step 1, 6."""

    user_id: str
    role: str
    department: str
    ai_data_policy: AiDataPolicy  # effective: user setting capped by role max


@dataclass(frozen=True, slots=True)
class Policy:
    """One validated, merged policy snapshot. Immutable; one per request (I14).

    Spec section 6. ``tree`` is the merged effective policy (explicit > profile >
    default); ``sources`` maps each control path to where its value came from.
    ``tree`` holds API keys, so it is excluded from ``repr``.
    """

    version_hash: str
    profile: Profile
    tree: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}), repr=False)
    sources: Mapping[str, ControlSource] = field(default_factory=lambda: MappingProxyType({}))
    disabled_controls: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Signature:
    """One entry of signatures.json. Spec section 9; CLAUDE.md "Policy and feed"."""

    id: str
    category: str
    severity: str
    applies_to: tuple[str, ...]
    type: str
    pattern: str


@dataclass(frozen=True, slots=True)
class SignatureFeed:
    """Loaded signatures.json with its own version (spec section 6, live reload)."""

    version: str
    signatures: tuple[Signature, ...] = ()


# ---------------------------------------------------------------------------
# HTTP bodies (pydantic v2)
# ---------------------------------------------------------------------------


class ChatMessage(BaseModel):
    """One OpenAI chat message as sent by the client. Untrusted data (I15)."""

    model_config = ConfigDict(extra="ignore")

    role: str
    content: str | list[dict[str, Any]] | None = None
    name: str | None = None
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None


class ChatRequest(BaseModel):
    """Body of POST /v1/chat/completions (spec section 13, Endpoints)."""

    model_config = ConfigDict(extra="ignore")

    model: str
    messages: list[ChatMessage]
    tools: list[dict[str, Any]] | None = None


class ChatResponse(BaseModel):
    """OpenAI-format chat completion returned to the client (spec section 4 step 10)."""

    id: str
    object: Literal["chat.completion"] = "chat.completion"
    created: int
    model: str
    choices: list[dict[str, Any]]
    usage: dict[str, int] | None = None


# ---------------------------------------------------------------------------
# Pipeline types
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Finding:
    """One inbound match: what kind, which mask token replaced it and the action. No value.

    ``token`` is empty when the control only logs (the text is left unchanged).
    """

    type: str
    token: str
    action: Literal["redact", "block", "log"] = "redact"


@dataclass(slots=True)
class SanitizedRequest:
    """Request after inbound inspection: masked messages, client tools, findings.

    Spec section 4 step 3. Contains mask tokens only, never raw values.
    """

    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]]
    findings: list[Finding] = field(default_factory=list)


@dataclass(slots=True)
class Binding:
    """One query_data call and its outcome. Spec section 5.

    ``value`` is raw database output and is excluded from ``repr`` (I8).
    """

    name: str  # placeholder, e.g. "{x1}"
    sql: str
    purpose: str
    expect: Expect
    status: BindingStatus | None = None  # None until resolution finishes
    value: Any = field(default=None, repr=False)
    label: Label | None = None
    disclosed: bool = False
    reason: str = ""
    tables: list[str] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    rows: int = 0
    truncated: bool = False
    latency_ms: float = 0.0
    # The exact string that passed validation and authorization; set by the authorizer and
    # compared with ``sql`` by the executor before running it (I4).
    approved_sql: str = field(default="", repr=False)
    # Who and under which policy version it was approved: (user_id, policy version_hash).
    # The executor runs it only for that user and that policy version (I4, I14).
    approved_for: tuple[str, str] = ("", "")


@dataclass(slots=True)
class ToolCall:
    """A client tool call proposed by the model. Arguments may hold placeholders or values.

    ``arguments`` is the parsed JSON object, or the raw string when the model's arguments
    were not a JSON object (tool authorization denies those).
    """

    id: str
    name: str
    arguments: dict[str, Any] | str = field(default_factory=dict, repr=False)


@dataclass(slots=True)
class ToolDecision:
    """Outcome of client tool authorization. Spec section 4 step 7, section 5."""

    tool: str
    verdict: ToolVerdict
    rule: str
    reason: str


@dataclass(slots=True)
class Decision:
    """Outcome of one check. ``reason`` is a short human-readable sentence."""

    stage: str
    control: str
    verdict: Verdict
    reason: str = ""
    latency_ms: float = 0.0


@dataclass(slots=True)
class LoopResult:
    """Output of the tool loop (spec section 4 steps 5-6).

    ``text`` is model-written and still contains placeholders.
    """

    text: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    bindings: dict[str, Binding] = field(default_factory=dict)
    iterations: int = 0
    decisions: list[Decision] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def block(self) -> Decision | None:
        """The decision that blocked the request (tool-name collision, budget, model failure), if any."""
        return next((d for d in self.decisions if d.verdict == "block"), None)


@dataclass(slots=True)
class Span:
    """A region of FilledText and who wrote it."""

    start: int
    end: int
    source: SpanSource
    binding: str | None = None  # placeholder name for gateway-inserted spans


@dataclass(slots=True)
class FilledText:
    """Final text after outbound fill, with spans. Spec section 4 step 8.

    ``text`` contains real values and is excluded from ``repr`` (I8).
    """

    text: str = field(repr=False)
    spans: list[Span] = field(default_factory=list)


@dataclass(slots=True)
class BindingOutcome:
    """Audit view of a Binding: everything except the value."""

    name: str
    sql: str
    purpose: str
    status: BindingStatus | None
    label: Label | None
    disclosed: bool
    reason: str
    tables: list[str]
    columns: list[str]
    rows: int
    truncated: bool
    latency_ms: float


@dataclass(slots=True)
class AuditRecord:
    """Exactly one per request, including 401s, blocks and crashes (I12). No values (I8)."""

    request_id: str
    timestamp: str  # ISO 8601, UTC
    policy_version: str
    feed_version: str
    verdict: Verdict
    user_id: str | None = None
    role: str | None = None
    department: str | None = None
    ai_data_policy: AiDataPolicy | None = None
    answer_model: str | None = None
    judge_model: str | None = None
    decisions: list[Decision] = field(default_factory=list)
    bindings: list[BindingOutcome] = field(default_factory=list)
    tool_decisions: list[ToolDecision] = field(default_factory=list)
    tool_iterations: int = 0
    disabled_controls: list[str] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    judge_tokens: int = 0
    cost_usd: float = 0.0
    step_latency_ms: dict[str, float] = field(default_factory=dict)
    total_latency_ms: float = 0.0
    prompt_text: str | None = None  # newest user message, masked; None if audit.log_prompt_text is none
