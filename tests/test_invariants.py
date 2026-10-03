"""One test per invariant I1-I19 (spec section 7). Owner: Person 4.

Skipped tests are un-skipped as their modules land. Never delete one:
``test_every_invariant_has_exactly_one_test`` fails if any I-number goes missing.
Each skipped body calls ``pytest.fail`` so un-skipping without implementing fails.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# I1 helper: AST scan for database connections
# ---------------------------------------------------------------------------

SQLITE_MODULES = {"sqlite3", "sqlite3.dbapi2", "_sqlite3"}
DYNAMIC_IMPORTERS = {"import_module", "__import__"}

# Files allowed to open a SQLite connection. Everything else, including all of
# gateway/ except the executor, must not.
EXECUTOR = "gateway/binding/executor.py"
ALLOWED = {EXECUTOR, "db/seed.py"}  # seed.py builds demo.db; it is not part of the gateway
ALLOWED_DIRS = ("tests/",)  # tests read the seeded file to verify it
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "build", "dist", ".pytest_cache"}


def find_db_connects(source: str) -> list[int]:
    """Line numbers where ``source`` reaches sqlite3.connect, however it is spelled.

    Catches ``sqlite3.connect``, ``import sqlite3 as s; s.connect``,
    ``from sqlite3 import connect [as c]``, ``from sqlite3 import *``,
    ``sqlite3.dbapi2.connect``, ``getattr(sqlite3, "connect")`` and dynamic imports
    of sqlite3. References count, not only calls: ``f = sqlite3.connect`` is a hit.
    Unparsable source is reported as a hit on line 0 (deny by default, I6).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [0]

    module_aliases: set[str] = set()
    connect_aliases: set[str] = set()
    hits: list[int] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in SQLITE_MODULES or a.name.startswith("sqlite3."):
                    module_aliases.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom) and (node.module or "") in SQLITE_MODULES | {"sqlite3"}:
            for a in node.names:
                if a.name in ("connect", "*"):
                    hits.append(node.lineno)
                    connect_aliases.add(a.asname or a.name)
                elif a.name == "dbapi2":
                    module_aliases.add(a.asname or a.name)

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "connect":
            base = node.value
            while isinstance(base, ast.Attribute):  # sqlite3.dbapi2.connect
                base = base.value
            if isinstance(base, ast.Name) and base.id in module_aliases:
                hits.append(node.lineno)
        elif isinstance(node, ast.Name) and node.id in connect_aliases and isinstance(node.ctx, ast.Load):
            hits.append(node.lineno)
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""
            consts = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            if name == "getattr" and "connect" in consts:
                hits.append(node.lineno)
            if name in DYNAMIC_IMPORTERS and any(c.split(".")[0] in {"sqlite3", "_sqlite3"} for c in consts):
                hits.append(node.lineno)
    return sorted(set(hits))


def _python_files() -> list[Path]:
    return [
        p
        for p in REPO_ROOT.rglob("*.py")
        if not (set(p.relative_to(REPO_ROOT).parts) & SKIP_DIRS)
        and not any(part.endswith(".egg-info") for part in p.parts)
    ]


def _is_allowed(rel: str) -> bool:
    return rel in ALLOWED or rel.startswith(ALLOWED_DIRS)


# ---------------------------------------------------------------------------
# Trust and access
# ---------------------------------------------------------------------------


def test_only_the_executor_opens_the_database() -> None:
    """I1. Single data door: no file outside the executor calls sqlite3.connect."""
    files = _python_files()
    assert any(p.relative_to(REPO_ROOT).as_posix() == EXECUTOR for p in files)
    offenders = {
        rel: lines
        for p in files
        if not _is_allowed(rel := p.relative_to(REPO_ROOT).as_posix())
        and (lines := find_db_connects(p.read_text(encoding="utf-8")))
    }
    assert offenders == {}, f"sqlite3.connect outside {EXECUTOR}: {offenders}"


@pytest.mark.parametrize(
    "source",
    [
        "import sqlite3\nsqlite3.connect('demo.db')",
        "import sqlite3 as s\nconn = s.connect('demo.db')",
        "from sqlite3 import connect\nconnect('demo.db')",
        "from sqlite3 import connect as c\nc('demo.db')",
        "from sqlite3 import *",
        "import sqlite3.dbapi2\nsqlite3.dbapi2.connect('x')",
        "from sqlite3 import dbapi2 as d\nd.connect('x')",
        "import sqlite3\nf = sqlite3.connect",
        "import sqlite3\ngetattr(sqlite3, 'connect')('x')",
        "import importlib\nimportlib.import_module('sqlite3')",
        "__import__('sqlite3')",
        "def broken(:\n",
    ],
    ids=["plain", "alias", "from", "from-alias", "star", "dbapi2", "dbapi2-from", "reference",
         "getattr", "import_module", "__import__", "unparsable"],
)
def test_db_connect_scanner_catches_every_spelling(source: str) -> None:
    """I1 scanner self-test: each way of reaching sqlite3.connect is found."""
    assert find_db_connects(source)


@pytest.mark.parametrize(
    "source",
    [
        "import sqlite3\nerr = sqlite3.Error",
        "conn = pool.connect()",
        "from gateway.binding.executor import execute",
        "socket.connect(('127.0.0.1', 11434))",
    ],
)
def test_db_connect_scanner_ignores_unrelated_code(source: str) -> None:
    """I1 scanner self-test: no false positives on other connect calls."""
    assert find_db_connects(source) == []


@pytest.mark.skip(reason="needs gateway/auth.py and gateway/pipeline.py")
def test_identity_comes_only_from_api_key() -> None:
    """I2. The principal comes from the API key; text in messages, tool results or model output never changes it."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/binding/sql_validator.py")
def test_gateway_owns_sql_parameters() -> None:
    """I3. Only :current_user, :current_role, :current_department are bound, by the gateway; any other parameter rejects the query."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/binding/executor.py")
def test_executor_runs_exactly_the_approved_sql() -> None:
    """I4. The exact SQL string that passed validation and authorization is executed; nothing is regenerated."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/binding/sql_validator.py and gateway/binding/executor.py")
def test_database_is_read_only_twice_enforced() -> None:
    """I5. Only single SELECTs pass validation; the connection is read-only and set_authorizer denies non-reads."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/binding/authorizer.py and gateway/agency/tool_authz.py")
def test_unknown_or_failing_checks_deny_by_default() -> None:
    """I6. Missing permissions, unknown tables, columns or tools, unparsable SQL and internal errors deny."""
    pytest.fail("not implemented")


# ---------------------------------------------------------------------------
# Model exposure
# ---------------------------------------------------------------------------


@pytest.mark.skip(reason="needs gateway/inbound/masker.py and gateway/agency/loop.py")
def test_model_sees_only_sanitized_messages() -> None:
    """I7. User messages and tool results are masked, history re-masked and tool definitions scanned before any model call."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/pipeline.py and gateway/audit.py")
def test_vault_never_leaves_the_request() -> None:
    """I8. Vault contents never appear in model input, logs or responses to anyone but the original user."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/binding/disclosure.py and gateway/inbound/history.py")
def test_hidden_values_never_reach_any_model_input() -> None:
    """I9. A value that fails the disclosure rule never appears in any model input, in this or later requests."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/binding/disclosure.py")
def test_disclosure_respects_labels_and_model_trust() -> None:
    """I10. Values above max_label_to_model are never disclosed; external models never receive sensitive values."""
    pytest.fail("not implemented")


# ---------------------------------------------------------------------------
# Agency and consumption
# ---------------------------------------------------------------------------


@pytest.mark.skip(reason="needs gateway/agency/tool_authz.py")
def test_client_tool_calls_are_authorized_before_the_client_sees_them() -> None:
    """I11. A client tool call reaches the client only if the role lists it and every argument rule, including egress, passes."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/agency/loop.py")
def test_tool_loop_is_bounded() -> None:
    """I12. At most max_tool_iterations loop calls, max_bindings_per_request queries and max_tokens on every call."""
    pytest.fail("not implemented")


# ---------------------------------------------------------------------------
# Output integrity
# ---------------------------------------------------------------------------


@pytest.mark.skip(reason="needs gateway/outbound/fill.py")
def test_fill_is_single_pass_and_literal() -> None:
    """I13. Inserted values are escaped and never interpreted as placeholders, markup or instructions."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/binding/disclosure.py and gateway/outbound/fill.py")
def test_denial_reveals_nothing() -> None:
    """I14. The model gets the same bare placeholder for every non-resolved outcome; strict uses one marker for all."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/outbound/output_filter.py and gateway/pipeline.py")
def test_output_filter_runs_on_every_answer_and_tool_call() -> None:
    """I15. The output filter runs on every final answer and every allowed tool call's arguments."""
    pytest.fail("not implemented")


# ---------------------------------------------------------------------------
# Governance
# ---------------------------------------------------------------------------


@pytest.mark.skip(reason="needs gateway/policy/loader.py and gateway/pipeline.py")
def test_each_request_uses_one_policy_version() -> None:
    """I16. A request is evaluated against one policy version, recorded in its audit record."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/audit.py and gateway/pipeline.py")
def test_every_request_writes_exactly_one_audit_record() -> None:
    """I17. Exactly one audit record per request, including blocked and failed ones; no raw secrets or values in logs."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/budget.py")
def test_budget_is_checked_before_every_model_call_and_query() -> None:
    """I18. No model call (answer, loop iteration, judge) and no query runs once the budget is exhausted."""
    pytest.fail("not implemented")


@pytest.mark.skip(reason="needs gateway/policy/loader.py and gateway/policy/profiles.py")
def test_guardrails_are_never_silently_disabled() -> None:
    """I19. A missing control inherits its profile value; only mode: off disables it; core controls cannot be disabled."""
    pytest.fail("not implemented")


# ---------------------------------------------------------------------------
# Guard: never delete an invariant test
# ---------------------------------------------------------------------------


def test_every_invariant_has_exactly_one_test() -> None:
    """Exactly one test per invariant I1-I19, identified by its docstring prefix."""
    numbers = [
        int(m.group(1))
        for name, fn in vars(sys.modules[__name__]).items()
        if name.startswith("test_") and callable(fn)
        and (m := re.match(r"I(\d+)\. ", (fn.__doc__ or "")))
    ]
    assert sorted(numbers) == list(range(1, 20))
