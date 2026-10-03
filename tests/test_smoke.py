"""Smoke test: every skeleton module imports. Owner: Person 4."""
from __future__ import annotations

import importlib

import pytest

MODULES = [
    "gateway",
    "gateway.main",
    "gateway.pipeline",
    "gateway.models",
    "gateway.auth",
    "gateway.budget",
    "gateway.audit",
    "gateway.telemetry",
    "gateway.policy",
    "gateway.policy.loader",
    "gateway.policy.profiles",
    "gateway.inbound",
    "gateway.inbound.masker",
    "gateway.inbound.history",
    "gateway.inbound.injection",
    "gateway.inbound.signatures",
    "gateway.inbound.judge",
    "gateway.llm",
    "gateway.llm.client",
    "gateway.llm.prompts",
    "gateway.agency",
    "gateway.agency.loop",
    "gateway.agency.tool_authz",
    "gateway.binding",
    "gateway.binding.sql_validator",
    "gateway.binding.authorizer",
    "gateway.binding.executor",
    "gateway.binding.disclosure",
    "gateway.outbound",
    "gateway.outbound.fill",
    "gateway.outbound.output_filter",
    "gateway.outbound.protected_index",
    "gateway.cli",
    "gateway.cli.fetch_feed",
    "gateway.cli.scan_model",
    "db.seed",
    "dashboard.app",
    "demo_agent.app",
]


@pytest.mark.parametrize("name", MODULES)
def test_every_skeleton_module_imports(name: str) -> None:
    importlib.import_module(name)
