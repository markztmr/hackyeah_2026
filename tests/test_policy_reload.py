"""Policy loading, profiles, precedence and live reload. Spec section 6; I16, I19. Owner: Person 1."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from gateway.policy.loader import (
    CORE_CONTROLS,
    PolicyError,
    PolicyStore,
    effective_policy,
    parse_policy,
    setting,
)
from gateway.policy.profiles import PROFILES, STRICT_DEFAULTS

REPO_ROOT = Path(__file__).resolve().parent.parent
SHIPPED = REPO_ROOT / "policy.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def base() -> dict[str, Any]:
    """The shipped policy.yaml as a dict the test may mutate."""
    return copy.deepcopy(yaml.safe_load(SHIPPED.read_text(encoding="utf-8")))


def _dump(data: dict[str, Any]) -> bytes:
    return yaml.safe_dump(data, sort_keys=False).encode("utf-8")


def _parse(data: dict[str, Any]):
    return parse_policy(_dump(data))


def _rewrite(path: Path, content: dict[str, Any] | str | bytes) -> None:
    """Write the file and move its mtime forward, as an editor save would.

    The explicit bump keeps the test independent of filesystem timestamp resolution.
    """
    old = path.stat().st_mtime_ns
    if isinstance(content, dict):
        content = _dump(content)
    elif isinstance(content, str):
        content = content.encode("utf-8")
    path.write_bytes(content)
    bumped = old + 2_000_000_000
    os.utime(path, ns=(bumped, bumped))


def _problems(exc: pytest.ExceptionInfo[PolicyError]) -> str:
    return " | ".join(exc.value.problems)


# ---------------------------------------------------------------------------
# Profiles (spec section 6 "Profiles")
# ---------------------------------------------------------------------------

PROFILE_TABLE: dict[str, tuple[Any, Any, Any]] = {
    "prompt_controls.semantic.block_threshold": (0.70, 0.80, 0.90),
    "prompt_controls.semantic.on_failure": ("block", "block", "allow_and_flag"),
    "prompt_controls.secrets.mode": ("block", "redact", "redact"),
    "prompt_controls.pii.mode": ("redact", "redact", "log"),
    "prompt_controls.injection.mode": ("block", "block", "log"),
    "sql_controls.select_star": ("reject", "expand", "expand"),
    "output_controls.echo_own_input": (False, True, True),
    "tool_controls.max_tool_iterations": (3, 4, 6),
    "budgets.default.tokens_per_day": (20_000, 50_000, 200_000),
}


@pytest.mark.parametrize("path", sorted(PROFILE_TABLE))
def test_every_profile_matches_the_spec_profile_table(path: str) -> None:
    for profile, expected in zip(("strict", "balanced", "relaxed"), PROFILE_TABLE[path]):
        assert PROFILES[profile][path] == expected, (profile, path)


def test_strict_profile_uses_one_marker_for_every_non_resolved_outcome() -> None:
    markers = {PROFILES["strict"][f"markers.{k}"] for k in ("denied", "rejected", "empty", "error")}
    assert markers == {"[UNAVAILABLE]"}


def test_balanced_and_relaxed_profiles_use_distinct_markers() -> None:
    for profile in ("balanced", "relaxed"):
        assert PROFILES[profile]["markers.denied"] == "[NOT AUTHORIZED]"
        assert PROFILES[profile]["markers.empty"] == "[NO DATA]"
        assert PROFILES[profile]["markers.rejected"] == "[UNAVAILABLE]"
        assert PROFILES[profile]["markers.error"] == "[UNAVAILABLE]"


def test_every_profile_setting_exists_in_the_strict_defaults() -> None:
    for profile, overrides in PROFILES.items():
        for path, value in overrides.items():
            node: Any = STRICT_DEFAULTS
            for part in path.split("."):
                assert part in node, (profile, path)
                node = node[part]
            if profile == "strict":
                assert node == value, path


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------


def test_shipped_policy_yaml_is_valid() -> None:
    p = parse_policy(SHIPPED.read_bytes())
    assert p.profile == "strict"
    assert set(setting(p, "users")) == {"anna", "marek", "piotr"}


def test_version_hash_is_sha256_of_the_file_bytes() -> None:
    raw = SHIPPED.read_bytes()
    assert parse_policy(raw).version_hash == hashlib.sha256(raw).hexdigest()


def test_a_comment_only_change_gives_a_new_version_hash() -> None:
    raw = SHIPPED.read_bytes()
    assert parse_policy(raw).version_hash != parse_policy(raw + b"\n# edited\n").version_hash


def test_unknown_top_level_key_is_rejected(base: dict[str, Any]) -> None:
    base["promt_controls"] = {"injection": {"mode": "block"}}
    with pytest.raises(PolicyError) as exc:
        _parse(base)
    assert "promt_controls" in _problems(exc)


def test_misspelled_key_inside_a_control_is_rejected(base: dict[str, Any]) -> None:
    base["prompt_controls"]["injection"] = {"mdoe": "block"}
    with pytest.raises(PolicyError) as exc:
        _parse(base)
    assert "prompt_controls.injection.mdoe" in _problems(exc)


@pytest.mark.parametrize(
    ("section", "key", "bad"),
    [
        ("tool_controls", "max_tool_iterations", "three"),
        ("tool_controls", "max_tool_iterations", True),
        ("sql_controls", "max_rows", 1.5),
        ("sql_controls", "max_rows", 0),
        ("output_controls", "echo_own_input", "yes please"),
        ("sql_controls", "select_star", "allow"),
        ("output_controls", "mode", "off"),
    ],
)
def test_wrong_type_or_value_is_rejected(base: dict[str, Any], section: str, key: str, bad: Any) -> None:
    base[section][key] = bad
    with pytest.raises(PolicyError) as exc:
        _parse(base)
    assert f"{section}.{key}" in _problems(exc)


def test_semantic_threshold_outside_zero_to_one_is_rejected(base: dict[str, Any]) -> None:
    base["prompt_controls"]["semantic"]["block_threshold"] = 1.5
    with pytest.raises(PolicyError):
        _parse(base)


def test_statements_other_than_select_are_rejected(base: dict[str, Any]) -> None:
    base["sql_controls"]["allow_statements"] = ["SELECT", "DELETE"]
    with pytest.raises(PolicyError) as exc:
        _parse(base)
    assert "sql_controls.allow_statements" in _problems(exc)


def test_user_with_unknown_role_is_rejected(base: dict[str, Any]) -> None:
    base["users"]["anna"]["role"] = "ceo"
    with pytest.raises(PolicyError) as exc:
        _parse(base)
    assert "users.anna.role" in _problems(exc)


def test_role_granting_an_unknown_table_is_rejected(base: dict[str, Any]) -> None:
    base["roles"]["intern"]["tables"]["payroll"] = {"scope": "all"}
    with pytest.raises(PolicyError) as exc:
        _parse(base)
    assert "roles.intern.tables.payroll" in _problems(exc)


def test_scope_self_on_a_table_without_owner_column_is_rejected(base: dict[str, Any]) -> None:
    base["roles"]["intern"]["tables"]["products"] = {"scope": "self"}
    with pytest.raises(PolicyError) as exc:
        _parse(base)
    assert "roles.intern.tables.products.scope" in _problems(exc)


def test_budget_for_an_unknown_role_is_rejected(base: dict[str, Any]) -> None:
    base["budgets"]["hr_manger"] = {"tokens_per_day": 1}
    with pytest.raises(PolicyError) as exc:
        _parse(base)
    assert "budgets.hr_manger" in _problems(exc)


def test_two_users_with_the_same_api_key_are_rejected(base: dict[str, Any]) -> None:
    base["users"]["marek"]["api_key"] = base["users"]["anna"]["api_key"]
    with pytest.raises(PolicyError) as exc:
        _parse(base)
    assert "users.marek.api_key" in _problems(exc)


def test_role_listing_the_builtin_query_data_tool_is_rejected(base: dict[str, Any]) -> None:
    base["roles"]["intern"]["tools"]["query_data"] = {}
    with pytest.raises(PolicyError):
        _parse(base)


def test_invalid_argument_regex_is_rejected(base: dict[str, Any]) -> None:
    base["roles"]["intern"]["tools"]["send_email"]["args"]["to"]["allow_pattern"] = "([a-z"
    with pytest.raises(PolicyError) as exc:
        _parse(base)
    assert "allow_pattern" in _problems(exc)


def test_duplicate_yaml_keys_are_rejected() -> None:
    raw = SHIPPED.read_bytes() + b"\nprofile: relaxed\n"
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_validation_errors_never_echo_values(base: dict[str, Any]) -> None:
    """I8: an API key with the wrong type must not appear in the error text."""
    base["users"]["anna"]["api_key"] = ["sk-live-9f8e7d6c5b4a"]
    with pytest.raises(PolicyError) as exc:
        _parse(base)
    assert "sk-live-9f8e7d6c5b4a" not in str(exc.value)


def test_yaml_syntax_errors_never_echo_file_content() -> None:
    raw = b"users:\n  anna: { api_key: sk-live-9f8e7d6c5b4a, role: [unclosed\n"
    with pytest.raises(PolicyError) as exc:
        parse_policy(raw)
    assert "sk-live-9f8e7d6c5b4a" not in str(exc.value)
    assert "line" in str(exc.value)


# ---------------------------------------------------------------------------
# Core controls cannot be disabled (I19)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "snippet",
    [
        "auth: { mode: off }",
        "authentication: { mode: \"off\" }",
        "sql_controls: { mode: off }",
        "sql_validation: { mode: off }",
        "authorization: { mode: off }",
        "executor: { mode: off }",
        "fill: { mode: off }",
        "audit: { mode: off }",
        "audit: off",
        "sql_controls: { sql_validation: { enabled: false } }",
    ],
)
def test_off_on_a_core_control_is_rejected(snippet: str) -> None:
    raw = SHIPPED.read_bytes() + b"\n" + snippet.encode()
    if snippet.startswith(("sql_controls", "audit")):
        # Replace the shipped section rather than duplicating the key.
        data = yaml.safe_load(SHIPPED.read_text(encoding="utf-8"))
        data.update(yaml.safe_load(snippet))
        raw = _dump(data)
    with pytest.raises(PolicyError) as exc:
        parse_policy(raw)
    assert "cannot be disabled" in _problems(exc)


def test_core_controls_cover_the_spec_list() -> None:
    assert set(CORE_CONTROLS) == {"authentication", "sql_validation", "authorization", "executor", "fill", "audit"}


# ---------------------------------------------------------------------------
# Precedence: explicit > profile > strict default
# ---------------------------------------------------------------------------


def test_explicit_value_wins_over_the_profile(base: dict[str, Any]) -> None:
    base["profile"] = "relaxed"
    base["prompt_controls"]["injection"] = {"mode": "block"}
    p = _parse(base)
    assert setting(p, "prompt_controls.injection.mode") == "block"
    assert p.sources["prompt_controls.injection.mode"] == "explicit"


def test_missing_setting_comes_from_the_profile(base: dict[str, Any]) -> None:
    base["profile"] = "balanced"
    del base["prompt_controls"]["semantic"]["block_threshold"]
    p = _parse(base)
    assert setting(p, "prompt_controls.semantic.block_threshold") == 0.80
    assert p.sources["prompt_controls.semantic.block_threshold"] == "profile"


def test_setting_outside_the_profile_table_comes_from_the_strict_default(base: dict[str, Any]) -> None:
    base["profile"] = "relaxed"
    del base["sql_controls"]["max_rows"]
    p = _parse(base)
    assert setting(p, "sql_controls.max_rows") == 50
    assert p.sources["sql_controls.max_rows"] == "default"


def test_deleted_control_inherits_its_profile_value(base: dict[str, Any]) -> None:
    """Spec section 6: deleting `injection` in relaxed gives `log`, not off."""
    base["profile"] = "relaxed"
    del base["prompt_controls"]["injection"]
    p = _parse(base)
    assert setting(p, "prompt_controls.injection.mode") == "log"
    assert p.sources["prompt_controls.injection.mode"] == "profile"
    assert "prompt_controls.injection" not in p.disabled_controls


def test_deleting_every_control_section_never_disables_anything(base: dict[str, Any]) -> None:
    for section in ("prompt_controls", "sql_controls", "tool_controls", "output_controls", "markers", "budgets"):
        base.pop(section, None)
    p = _parse(base)
    assert p.disabled_controls == ()
    assert setting(p, "prompt_controls.injection.mode") == "block"


def test_missing_profile_means_strict(base: dict[str, Any]) -> None:
    del base["profile"]
    p = _parse(base)
    assert p.profile == "strict"
    assert setting(p, "tool_controls.max_tool_iterations") == 3


def test_mode_off_disables_the_control_and_lists_it(base: dict[str, Any]) -> None:
    base["profile"] = "relaxed"
    base["prompt_controls"]["injection"] = {"mode": "off"}
    p = _parse(base)
    assert setting(p, "prompt_controls.injection.mode") == "off"
    assert "prompt_controls.injection" in p.disabled_controls


def test_unquoted_yaml_off_counts_as_mode_off() -> None:
    """PyYAML reads bare `off` as False; it must still mean off, not a type error."""
    data = yaml.safe_load(SHIPPED.read_text(encoding="utf-8"))
    data.pop("prompt_controls")
    raw = _dump(data) + b"prompt_controls:\n  injection: { mode: off }\n"
    p = parse_policy(raw)
    assert setting(p, "prompt_controls.injection.mode") == "off"
    assert "prompt_controls.injection" in p.disabled_controls


def test_policy_tree_is_immutable(base: dict[str, Any]) -> None:
    p = _parse(base)
    with pytest.raises(TypeError):
        p.tree["sql_controls"]["max_rows"] = 10_000  # type: ignore[index]


# ---------------------------------------------------------------------------
# Live reload (I16)
# ---------------------------------------------------------------------------


def test_changed_threshold_applies_to_the_next_request(policy: Path, base: dict[str, Any]) -> None:
    store = PolicyStore(policy)
    in_flight = store.snapshot()
    base["prompt_controls"]["semantic"]["block_threshold"] = 0.55
    _rewrite(policy, base)

    next_request = store.snapshot()
    assert setting(next_request, "prompt_controls.semantic.block_threshold") == 0.55
    assert next_request.version_hash != in_flight.version_hash
    # The request already in flight keeps its snapshot.
    assert setting(in_flight, "prompt_controls.semantic.block_threshold") == 0.70


def test_unchanged_file_is_not_reloaded(policy: Path) -> None:
    store = PolicyStore(policy)
    assert store.snapshot() is store.snapshot()


def test_invalid_yaml_keeps_the_old_policy_and_records_the_error(policy: Path) -> None:
    store = PolicyStore(policy)
    good = store.snapshot()
    _rewrite(policy, "users: [unclosed\n")

    assert store.snapshot() is good
    status = store.status()
    assert status["error"]
    assert status["version"] == good.version_hash


def test_policy_failing_validation_keeps_the_old_policy(policy: Path, base: dict[str, Any]) -> None:
    store = PolicyStore(policy)
    good = store.snapshot()
    base["users"]["anna"]["role"] = "ceo"
    _rewrite(policy, base)

    assert store.snapshot() is good
    assert "users.anna.role" in store.status()["error"]


def test_off_on_a_core_control_during_reload_keeps_the_old_policy(policy: Path, base: dict[str, Any]) -> None:
    store = PolicyStore(policy)
    good = store.snapshot()
    base["audit"] = {"mode": "off"}
    _rewrite(policy, base)

    assert store.snapshot() is good
    assert "cannot be disabled" in store.status()["error"]


def test_fixing_the_file_clears_the_error(policy: Path, base: dict[str, Any]) -> None:
    store = PolicyStore(policy)
    _rewrite(policy, "users: [unclosed\n")
    store.snapshot()
    assert store.status()["error"]

    base["tool_controls"]["max_tool_iterations"] = 2
    _rewrite(policy, base)
    assert setting(store.snapshot(), "tool_controls.max_tool_iterations") == 2
    assert store.status()["error"] is None


def test_deleted_policy_file_keeps_the_old_policy(policy: Path) -> None:
    store = PolicyStore(policy)
    good = store.snapshot()
    policy.unlink()

    assert store.snapshot() is good
    assert store.status()["error"]


def test_invalid_policy_at_startup_refuses_to_start(policy: Path) -> None:
    policy.write_text("users: [unclosed\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        PolicyStore(policy)


def test_manual_reload_reports_the_validation_error(policy: Path, base: dict[str, Any]) -> None:
    store = PolicyStore(policy)
    base["roles"]["intern"]["tables"]["payroll"] = {"scope": "all"}
    policy.write_bytes(_dump(base))  # no mtime bump: manual reload must still re-read

    status = store.reload()
    assert "roles.intern.tables.payroll" in status["error"]


def test_manual_reload_picks_up_a_change_without_an_mtime_change(policy: Path, base: dict[str, Any]) -> None:
    store = PolicyStore(policy)
    before = store.snapshot()
    stat = policy.stat()
    base["sql_controls"]["max_rows"] = 25
    policy.write_bytes(_dump(base))
    os.utime(policy, ns=(stat.st_atime_ns, stat.st_mtime_ns))

    status = store.reload()
    assert status["error"] is None
    assert status["version"] != before.version_hash
    assert setting(store.snapshot(), "sql_controls.max_rows") == 25


# ---------------------------------------------------------------------------
# Effective view (GET /policy/effective)
# ---------------------------------------------------------------------------


def test_effective_view_lists_every_control_with_value_and_source(base: dict[str, Any]) -> None:
    base["profile"] = "relaxed"
    del base["prompt_controls"]["injection"]
    base["prompt_controls"]["pii"] = {"mode": "off"}
    view = effective_policy(_parse(base))

    controls = view["controls"]
    assert controls["prompt_controls.injection.mode"] == {"value": "log", "source": "profile"}
    assert controls["prompt_controls.pii.mode"] == {"value": "off", "source": "explicit"}
    assert controls["sql_controls.max_rows"]["source"] == "explicit"
    assert view["disabled_controls"] == ["prompt_controls.pii"]
    assert view["profile"] == "relaxed"
    for name in CORE_CONTROLS:
        assert controls[f"core.{name}"]["value"] == "on"
    # Every leaf of the strict defaults is listed.
    assert set(_leaf_paths(STRICT_DEFAULTS)) <= set(controls)


def test_effective_view_is_json_serializable(base: dict[str, Any]) -> None:
    json.dumps(effective_policy(_parse(base)))


def test_effective_view_never_contains_api_keys(base: dict[str, Any]) -> None:
    text = json.dumps(effective_policy(_parse(base)))
    for user in base["users"].values():
        assert user["api_key"] not in text


def _leaf_paths(tree: dict[str, Any], prefix: str = "") -> list[str]:
    out: list[str] = []
    for k, v in tree.items():
        if isinstance(v, dict) and v:
            out.extend(_leaf_paths(v, f"{prefix}{k}."))
        elif not isinstance(v, dict):
            out.append(f"{prefix}{k}")
    return out
