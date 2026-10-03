"""Model allowlist and digest pinning (spec section 4 step 2, section 6 'models', section 9).

Owner: Person 4 (model part and digests: Person 1). Ollama /api/tags is faked by the
autouse ``ollama_tags`` fixture (every pin installed unless a test says otherwise).
"""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from gateway.budget import check_model_and_budget, resolve_model
from gateway.llm import digests
from gateway.llm.client import StubModel, text
from gateway.llm.digests import installed_digests as real_installed_digests
from gateway.models import Principal
from gateway.policy.loader import parse_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
ANNA = Principal("anna", "intern", "sales", "deny")
ANNA_KEY = {"Authorization": "Bearer demo-anna"}
OTHER = "sha256:" + "ab" * 32
QWEN_3B_PIN = "sha256:357c53fb659c5076de1d65ccb0b397446227b71a42be9d1603d46168015c9e4b"


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


# ---------------------------------------------------------------------------
# Digest pinning (spec section 9, section 8 "digest differs from the pinned digest")
# ---------------------------------------------------------------------------


def test_pinned_model_with_matching_digest_is_used(base: dict[str, Any]) -> None:
    model, d = resolve_model("qwen2.5:3b", _policy(base))
    assert (model, d.verdict) == ("qwen2.5:3b", "allow")


def test_digest_mismatch_blocks_the_model(base: dict[str, Any], ollama_tags: dict[str, Any]) -> None:
    ollama_tags["installed"]["qwen2.5:3b"] = OTHER
    model, d = resolve_model("qwen2.5:3b", _policy(base))
    assert (model, d.verdict, d.control) == (None, "block", "models.digest")
    assert d.reason == "The model's digest does not match the pinned digest; model blocked."


def test_digest_mismatch_of_one_model_leaves_the_others_usable(base: dict[str, Any], ollama_tags: dict[str, Any]) -> None:
    ollama_tags["installed"]["qwen2.5:1.5b"] = OTHER
    policy = _policy(base)
    assert resolve_model("qwen2.5:3b", policy)[0] == "qwen2.5:3b"
    assert resolve_model("qwen2.5:1.5b", policy)[0] is None


def test_digest_mismatch_blocks_a_substituted_answer_model(base: dict[str, Any], ollama_tags: dict[str, Any]) -> None:
    base["models"]["on_unlisted"] = "substitute"
    ollama_tags["installed"]["qwen2.5:3b"] = OTHER
    model, d = resolve_model("gpt-4o", _policy(base))
    assert (model, d.verdict, d.control) == (None, "block", "models.digest")


def test_digest_mismatch_blocks_through_check_model_and_budget(base: dict[str, Any], ollama_tags: dict[str, Any]) -> None:
    """The judge's pre-call check goes through check_model_and_budget, so a swapped judge is blocked too."""
    ollama_tags["installed"]["qwen2.5:1.5b"] = OTHER
    d = check_model_and_budget(ANNA, "qwen2.5:1.5b", 100, _policy(base))
    assert (d.verdict, d.control) == ("block", "models.digest")


def test_pinned_model_that_is_not_installed_is_blocked(base: dict[str, Any], ollama_tags: dict[str, Any]) -> None:
    ollama_tags["installed"]["qwen2.5:3b"] = None
    model, d = resolve_model("qwen2.5:3b", _policy(base))
    assert (model, d.verdict) == (None, "block")
    assert "not installed" in d.reason


def test_pinned_model_is_blocked_when_ollama_tags_cannot_be_read(base: dict[str, Any], ollama_tags: dict[str, Any]) -> None:
    ollama_tags["down"] = True
    model, d = resolve_model("qwen2.5:3b", _policy(base))
    assert (model, d.verdict) == (None, "block")
    assert "could not be verified" in d.reason


def test_unverified_digests_are_rechecked_after_the_retry_interval(
    base: dict[str, Any], ollama_tags: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(base)
    ollama_tags["down"] = True
    assert resolve_model("qwen2.5:3b", policy)[0] is None
    ollama_tags["down"] = False
    assert resolve_model("qwen2.5:3b", policy)[0] is None  # still within RETRY_S: cached
    monkeypatch.setattr(digests, "RETRY_S", 0.0)
    assert resolve_model("qwen2.5:3b", policy)[0] == "qwen2.5:3b"


def test_a_verified_result_is_cached_until_a_forced_check(base: dict[str, Any], ollama_tags: dict[str, Any]) -> None:
    policy = _policy(base)
    assert resolve_model("qwen2.5:3b", policy)[0] == "qwen2.5:3b"
    calls = ollama_tags["calls"]
    resolve_model("qwen2.5:3b", policy)
    assert ollama_tags["calls"] == calls
    ollama_tags["installed"]["qwen2.5:3b"] = OTHER
    digests.check_digests(policy, force=True)
    assert resolve_model("qwen2.5:3b", policy)[0] is None


@pytest.mark.parametrize("pin", ["sha256:<pin>", "sha256:1234", "md5:" + "ab" * 32, "sha256:" + "zz" * 32])
def test_placeholder_or_malformed_pin_never_matches(base: dict[str, Any], pin: str) -> None:
    base["models"]["allowed"][0]["digest"] = pin
    model, d = resolve_model("qwen2.5:3b", _policy(base))
    assert (model, d.verdict) == (None, "block")


def test_pin_matches_without_prefix_and_in_upper_case(base: dict[str, Any], ollama_tags: dict[str, Any]) -> None:
    ollama_tags["installed"]["qwen2.5:3b"] = QWEN_3B_PIN.removeprefix("sha256:")
    base["models"]["allowed"][0]["digest"] = QWEN_3B_PIN.removeprefix("sha256:").upper()
    assert resolve_model("qwen2.5:3b", _policy(base))[0] == "qwen2.5:3b"


def test_unpinned_model_is_allowed_without_a_digest_check(base: dict[str, Any], ollama_tags: dict[str, Any]) -> None:
    """External models have no digest (policy.yaml external example); pinning applies to Ollama models."""
    base["models"]["allowed"].append({"name": "gpt-4o-mini"})
    ollama_tags["down"] = True
    model, d = resolve_model("gpt-4o-mini", _policy(base))
    assert (model, d.verdict) == ("gpt-4o-mini", "allow")


def test_untagged_name_matches_the_latest_tag() -> None:
    assert digests._lookup("llama3.2", {"llama3.2:latest": "a" * 64}) == "a" * 64
    assert digests._lookup("qwen2.5:3b", {"qwen2.5:3b:latest": "a" * 64}) is None


def test_fetch_installed_reads_api_tags_at_the_ollama_root(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    class Reply:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, Any]:
            return {"models": [{"name": "qwen2.5:3b", "model": "qwen2.5:3b", "digest": "AB" * 32}]}

    monkeypatch.setattr(digests.httpx, "get", lambda url, timeout: seen.append(url) or Reply())
    assert digests.fetch_installed("http://localhost:11434/v1/") == {"qwen2.5:3b": "ab" * 32}
    assert seen == ["http://localhost:11434/api/tags"]


def test_unreachable_ollama_gives_no_installed_digests(base: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(url: str, timeout: float) -> Any:
        raise digests.httpx.ConnectError("refused")

    monkeypatch.setattr(digests.httpx, "get", refuse)
    assert real_installed_digests(_policy(base)) is None


def test_request_for_a_swapped_model_is_blocked_before_any_model_call(
    client: TestClient, stub: StubModel, judge_stub: StubModel, ollama_tags: dict[str, Any], fake_steps: Any,
) -> None:
    ollama_tags["installed"]["qwen2.5:3b"] = OTHER
    client.post("/policy/reload")  # the forced re-check a reload does
    stub.add(text("hello"))
    r = client.post("/v1/chat/completions", headers=ANNA_KEY,
                    json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "Hi"}]})
    assert r.headers["x-acl-verdict"] == "block"
    assert "pinned digest" in r.json()["choices"][0]["message"]["content"]
    assert stub.calls == [] and judge_stub.calls == []


def test_swapped_judge_model_blocks_the_request(
    client: TestClient, stub: StubModel, judge_stub: StubModel, ollama_tags: dict[str, Any], fake_steps: Any,
) -> None:
    ollama_tags["installed"]["qwen2.5:1.5b"] = OTHER
    client.post("/policy/reload")
    stub.add(text("hello"))
    r = client.post("/v1/chat/completions", headers=ANNA_KEY,
                    json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "Hi"}]})
    assert r.headers["x-acl-verdict"] == "block"
    assert stub.calls == [] and judge_stub.calls == []


def test_digests_are_checked_at_startup_and_on_reload(client: TestClient, ollama_tags: dict[str, Any]) -> None:
    assert ollama_tags["calls"] >= 1  # lifespan
    before = ollama_tags["calls"]
    client.post("/policy/reload")
    assert ollama_tags["calls"] == before + 1


def test_health_reports_a_digest_mismatch(client: TestClient, ollama_tags: dict[str, Any]) -> None:
    ollama_tags["installed"]["qwen2.5:3b"] = OTHER
    body = client.get("/health").json()
    assert body["status"] == "degraded"
    assert body["digests"]["ok"] is False
    assert body["digests"]["models"]["qwen2.5:3b"]["status"] == "mismatch"
    assert body["digests"]["models"]["qwen2.5:1.5b"]["status"] == "ok"


def test_health_reports_pinned_digests_as_ok(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body["digests"]["ok"] is True
    assert body["digests"]["models"]["qwen2.5:3b"] == {
        "status": "ok", "pinned": QWEN_3B_PIN[:19], "installed": QWEN_3B_PIN[:19]}


@pytest.mark.live
def test_policy_pins_match_the_installed_ollama_models() -> None:
    """policy.yaml's pins are the digests of the models pulled for the demo."""
    installed = digests.fetch_installed("http://127.0.0.1:11434/v1")
    for m in yaml.safe_load((REPO_ROOT / "policy.yaml").read_text(encoding="utf-8"))["models"]["allowed"]:
        assert installed.get(m["name"]) == digests.normalize_digest(m["digest"]), m["name"]
