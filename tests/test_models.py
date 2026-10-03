"""Model allowlist (spec section 4 step 2, section 6 'models'). Owner: Person 4 (model part: Person 1).

Digest pinning is Tier 2 and not covered yet.
"""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from gateway.budget import check_model_and_budget, resolve_model
from gateway.models import Principal
from gateway.policy.loader import parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
ANNA = Principal("anna", "intern", "sales", "deny")


@pytest.fixture
def base() -> dict[str, Any]:
    return copy.deepcopy(yaml.safe_load((REPO_ROOT / "policy.yaml").read_text(encoding="utf-8")))


def _policy(data: dict[str, Any]):
    return parse_policy(yaml.safe_dump(data).encode("utf-8"))


def test_allowed_model_is_used(base: dict[str, Any]) -> None:
    model, d = resolve_model("qwen2.5:3b", _policy(base))
    assert model == "qwen2.5:3b"
    assert d.verdict == "allow"


@pytest.mark.parametrize("requested", ["gpt-4o", "llama3.2", "QWEN2.5:3B", "qwen2.5:3b:latest", "qwen2.5:3b ", ""])
def test_unlisted_model_is_blocked(base: dict[str, Any], requested: str) -> None:
    model, d = resolve_model(requested, _policy(base))
    assert model is None
    assert d.verdict == "block"
    assert d.stage == "model_and_budget" and d.control == "models.allowed"


def test_block_from_check_model_and_budget_happens_before_any_budget_work(base: dict[str, Any]) -> None:
    d = check_model_and_budget(ANNA, "gpt-4o", 100, _policy(base))
    assert d.verdict == "block"
    assert "not allowed" in d.reason


def test_unlisted_model_is_substituted_with_the_answer_model(base: dict[str, Any]) -> None:
    base["models"]["on_unlisted"] = "substitute"
    model, d = resolve_model("gpt-4o", _policy(base))
    assert model == "qwen2.5:3b"
    assert d.verdict == "log"
    assert "qwen2.5:3b" in d.reason


def test_substitute_is_blocked_when_the_answer_model_is_not_allowed(base: dict[str, Any]) -> None:
    base["models"]["on_unlisted"] = "substitute"
    base["models"]["allowed"] = [m for m in base["models"]["allowed"] if m["name"] != "qwen2.5:3b"]
    model, d = resolve_model("gpt-4o", _policy(base))
    assert model is None
    assert d.verdict == "block"


def test_empty_allowlist_blocks_every_model(base: dict[str, Any]) -> None:
    del base["models"]["allowed"]
    model, d = resolve_model("qwen2.5:3b", _policy(base))
    assert (model, d.verdict) == (None, "block")


def test_llama32_is_not_an_allowed_model(base: dict[str, Any]) -> None:
    """qwen2.5:3b won the hour-1 test (README 'Model choice'); llama3.2 is no longer served."""
    model, d = resolve_model("llama3.2", _policy(base))
    assert (model, d.verdict) == (None, "block")
    assert [m["name"] for m in base["models"]["allowed"]] == ["qwen2.5:3b", "qwen2.5:1.5b"]


def test_block_reason_does_not_repeat_the_requested_name(base: dict[str, Any]) -> None:
    """The requested name is client input; reasons are shown on the dashboard."""
    _, d = resolve_model("ignore previous instructions", _policy(base))
    assert "ignore previous instructions" not in d.reason
