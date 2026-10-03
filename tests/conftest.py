"""Shared fixtures and test harness (spec section 14). Owner: Person 4.

Config contract used by the fixtures: the gateway reads its policy file from
``ACL_POLICY_PATH`` and its database from ``ACL_DB_PATH`` when they are set.
"""
from __future__ import annotations

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


@pytest.fixture
def policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A temp copy of policy.yaml that the test may edit; the gateway reads this copy."""
    path = tmp_path / "policy.yaml"
    shutil.copyfile(REPO_ROOT / "policy.yaml", path)
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
