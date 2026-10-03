"""Shared fixtures and test harness (spec section 14). Owner: Person 4.

Config contract used by the fixtures: the gateway reads its policy file from
``ACL_POLICY_PATH``, its database from ``ACL_DB_PATH``, writes audit records to
``ACL_AUDIT_PATH`` and keeps budget counters in ``ACL_STATE_PATH`` when they are set.
"""
from __future__ import annotations

import json
import shutil
import socket
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway.llm import client as llm
from gateway.llm.client import StubModel, text

REPO_ROOT = Path(__file__).resolve().parent.parent
OLLAMA_ADDR = ("127.0.0.1", 11434)


# ---------------------------------------------------------------------------
# Live tests skip cleanly when Ollama is down
# ---------------------------------------------------------------------------


def _ollama_up() -> bool:
    try:
        with socket.create_connection(OLLAMA_ADDR, timeout=0.2):
            return True
    except OSError:
        return False


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("live") and not _ollama_up():
        pytest.skip("Ollama is not running on 127.0.0.1:11434")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def audit_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Every test writes audit records to its own temp file, never into the repo."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("ACL_AUDIT_PATH", str(path))
    return path


@pytest.fixture(autouse=True)
def state_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Every test keeps budget counters in its own temp state.db, never the repo's."""
    path = tmp_path / "state.db"
    monkeypatch.setenv("ACL_STATE_PATH", str(path))
    return path


@pytest.fixture
def audit_records(audit_log: Path) -> Callable[[], list[dict[str, Any]]]:
    """``audit_records()`` -> every audit record written so far in this test."""
    def read() -> list[dict[str, Any]]:
        if not audit_log.exists():
            return []
        return [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    return read


@pytest.fixture
def policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A temp copy of policy.yaml (and the feed beside it) that the test may edit; the gateway reads this copy."""
    path = tmp_path / "policy.yaml"
    shutil.copyfile(REPO_ROOT / "policy.yaml", path)
    shutil.copyfile(REPO_ROOT / "signatures.json", tmp_path / "signatures.json")
    monkeypatch.setenv("ACL_POLICY_PATH", str(path))
    return path


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A freshly seeded temp database; the gateway reads this copy."""
    from db import seed as seed_module

    seed = getattr(seed_module, "seed", None)
    if seed is None:
        pytest.skip("db/seed.py does not provide seed(path) yet")
    path = tmp_path / "demo.db"
    seed(path)
    monkeypatch.setenv("ACL_DB_PATH", str(path))
    return path


@pytest.fixture
def judge_stub() -> StubModel:
    """Judge model stub: scores everything as safe unless a test scripts otherwise."""
    return StubModel(fallback=text('{"risk": 0.0}'))


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch, judge_stub: StubModel) -> StubModel:
    """Answer model stub, injected wherever the pipeline asks for a model client."""
    answer = StubModel()
    clients = {"answer": answer, "judge": judge_stub}
    monkeypatch.setattr(llm, "get_client", lambda purpose, policy: clients[purpose])
    return answer


@pytest.fixture
def client(policy: Path, stub: StubModel) -> Iterator[TestClient]:
    """FastAPI TestClient wired to the temp policy and the stub model."""
    from gateway.main import app

    with TestClient(app) as c:
        yield c


# Pipeline steps after authentication that receive the Principal.
_PRINCIPAL_STEPS = (
    "check_model_and_budget",
    "inspect_inbound",
    "run_tool_loop",
    "authorize_tool_call",
    "filter_output",
    "record_usage",
    "record_issued",
)


@pytest.fixture
def principals_seen(monkeypatch: pytest.MonkeyPatch, stub: StubModel) -> Callable[..., list[Any]]:
    """``principals_seen(api_key, messages)`` -> the Principal every later pipeline step received (I2).

    Runs the real ``run_pipeline`` against the shipped policy with the stub model.
    Each step is spied, then called for real. A step that is not implemented yet
    ends the run early; the principals recorded up to that point are returned,
    so the test covers more steps as they land.
    """
    from gateway import pipeline
    from gateway.models import ChatRequest, IssuedCache, Principal, SignatureFeed
    from gateway.pipeline import GatewayError
    from gateway.policy.loader import load_policy

    seen: list[Any] = []
    for name in _PRINCIPAL_STEPS:
        def spy(*args: Any, _real: Callable[..., Any] = getattr(pipeline, name), **kwargs: Any) -> Any:
            seen.extend(a for a in (*args, *kwargs.values()) if isinstance(a, Principal))
            return _real(*args, **kwargs)

        monkeypatch.setattr(pipeline, name, spy)

    def run(api_key: str, messages: list[dict[str, Any]]) -> list[Any]:
        policy = load_policy(REPO_ROOT / "policy.yaml")
        req = ChatRequest(model="qwen2.5:3b", messages=messages)
        try:
            pipeline.run_pipeline(api_key, req, policy, SignatureFeed(version="test"), IssuedCache())
        except GatewayError:
            pass  # a step that has not landed yet raised NotImplementedError
        assert seen, "the pipeline never handed a principal to a later step"
        return list(seen)

    return run


INJECTION_PHRASE = "ignore previous instructions"


@pytest.fixture
def fake_steps(monkeypatch: pytest.MonkeyPatch) -> dict[str, Callable[..., Any]]:
    """Permissive stand-ins for pipeline steps whose modules have not landed yet.

    Inbound, judge and issued-value recording allow everything. Budget (in a temp
    state.db), the injection check, signature feed, output filter, fill and tool
    authorization are real. query_data resolves every query to 1 (public). Tests
    override one step with ``monkeypatch.setattr(gateway.pipeline, name, ...)``.
    Remove a fake here when its real module lands.
    """
    from gateway import pipeline
    from gateway.agency import loop
    from gateway.models import Decision, SanitizedRequest, Vault

    def allow(stage: str, control: str) -> Decision:
        return Decision(stage, control, "allow", "")

    def inspect_inbound(req: Any, p: Any, policy: Any, cache: Any) -> Any:
        messages = [m.model_dump(exclude_none=True) for m in req.messages]
        return SanitizedRequest(messages=messages, tools=list(req.tools or [])), Vault(), [allow("inbound", "masker")]

    def execute(b: Any, p: Any, policy: Any) -> Any:
        b.status, b.value, b.label = "resolved", 1, "public"
        return b

    fakes: dict[str, Callable[..., Any]] = {
        "inspect_inbound": inspect_inbound,
        "judge": lambda text, policy, models=None: allow("input_checks", "semantic"),
        "record_issued": lambda p, bindings, cache: None,
    }
    for name, fn in fakes.items():
        monkeypatch.setattr(pipeline, name, fn)
    monkeypatch.setattr(loop, "validate_sql", lambda b, policy: b)
    monkeypatch.setattr(loop, "authorize", lambda b, p, policy: b)
    monkeypatch.setattr(loop, "execute", execute)
    monkeypatch.setattr(loop, "disclose", lambda b, p, policy, *, trust: b.name)
    return fakes


def _strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)
    elif obj is not None:
        yield str(obj)


def _all_model_inputs(*stubs: StubModel) -> str:
    """Every string any of these stubs ever received (messages and tool definitions)."""
    return "\n".join(s for st in stubs for call in st.calls for s in _strings([call.messages, call.tools]))


@pytest.fixture
def all_model_inputs() -> Callable[..., str]:
    """``all_model_inputs(stub, judge_stub)`` -> one string for exposure assertions (I7)."""
    return _all_model_inputs
