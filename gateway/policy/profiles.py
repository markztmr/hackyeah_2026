"""Strict / balanced / relaxed presets. Spec section 6 'Profiles'. Owner: Person 1.

``STRICT_DEFAULTS`` is the full control tree used when neither the file nor the
profile sets a value. ``PROFILES`` holds the profile table as dotted paths into
that tree. Resolution order (in the loader): explicit > profile > strict default.
"""
from __future__ import annotations

from typing import Any

from gateway.models import Profile

UNAVAILABLE = "[UNAVAILABLE]"

STRICT_DEFAULTS: dict[str, Any] = {
    "models": {
        "answer": {
            "provider": "ollama",
            "base_url": "http://localhost:11434/v1",
            "name": "llama3.2",
            "trust": "local",
            "max_tokens": 512,
            "timeout_s": 30.0,
        },
        "judge": {
            "provider": "ollama",
            "base_url": "http://localhost:11434/v1",
            "name": "qwen2.5:1.5b",
            "trust": "local",
            "max_tokens": 32,
            "timeout_s": 10.0,
        },
        "allowed": [],
        "on_unlisted": "block",
    },
    # Structural sections: no defaults, only what the file lists (deny by default).
    "users": {},
    "data": {"tables": {}},
    "roles": {},
    "prompt_controls": {
        "secrets": {"mode": "block"},
        "pii": {"mode": "redact", "types": ["email", "phone", "card", "pesel", "iban"]},
        "injection": {"mode": "block"},
        "signatures": {"mode": "block", "feed": "signatures.json"},
        "semantic": {"enabled": True, "block_threshold": 0.70, "on_failure": "block"},
        "tool_definitions": {"mode": "block"},
        "history_remask": {"enabled": True, "ttl_minutes": 60},
    },
    "sql_controls": {
        "allow_statements": ["SELECT"],
        "allowed_functions": [
            "count", "sum", "avg", "min", "max", "round", "abs", "coalesce", "ifnull",
            "lower", "upper", "length", "date", "strftime",
        ],
        "select_star": "reject",
        "scope_enforcement": "reject",
        "aggregates": "column_access",
        "recursive_cte": "reject",
        "max_rows": 50,
        "timeout_ms": 500,
        "max_bindings_per_request": 10,
    },
    "tool_controls": {
        "max_tool_iterations": 3,
        "unknown_tool": "deny",
        "placeholder_egress": "deny",
    },
    "output_controls": {
        "mode": "redact",
        "echo_own_input": False,
        "protected_values": {"enabled": True, "min_digits": 4},
        "escape": "markdown",
    },
    "markers": {
        "denied": UNAVAILABLE,
        "rejected": UNAVAILABLE,
        "empty": UNAVAILABLE,
        "error": UNAVAILABLE,
        "prior_value": "[PRIOR_VALUE]",
        "all_denied_message": None,
    },
    "budgets": {
        "default": {"tokens_per_day": 20_000, "requests_per_minute": 10, "cost_per_day_usd": 0.50},
        "count_judge_tokens": True,
        "store": "state.db",
    },
    "pricing_per_1k_tokens": {},
    "audit": {
        "path": "logs/audit.jsonl",
        "log_prompt_text": "masked",
        "hash_chain": False,
    },
    "dashboard": {"refresh_seconds": 2},
}

# Spec section 6 profile table. Every profile lists the same paths.
PROFILES: dict[Profile, dict[str, Any]] = {
    "strict": {
        "prompt_controls.semantic.block_threshold": 0.70,
        "prompt_controls.semantic.on_failure": "block",
        "prompt_controls.secrets.mode": "block",
        "prompt_controls.pii.mode": "redact",
        "prompt_controls.injection.mode": "block",
        "markers.denied": UNAVAILABLE,
        "markers.rejected": UNAVAILABLE,
        "markers.empty": UNAVAILABLE,
        "markers.error": UNAVAILABLE,
        "sql_controls.select_star": "reject",
        "output_controls.echo_own_input": False,
        "tool_controls.max_tool_iterations": 3,
        "budgets.default.tokens_per_day": 20_000,
    },
    "balanced": {
        "prompt_controls.semantic.block_threshold": 0.80,
        "prompt_controls.semantic.on_failure": "block",
        "prompt_controls.secrets.mode": "redact",
        "prompt_controls.pii.mode": "redact",
        "prompt_controls.injection.mode": "block",
        "markers.denied": "[NOT AUTHORIZED]",
        "markers.rejected": UNAVAILABLE,
        "markers.empty": "[NO DATA]",
        "markers.error": UNAVAILABLE,
        "sql_controls.select_star": "expand",
        "output_controls.echo_own_input": True,
        "tool_controls.max_tool_iterations": 4,
        "budgets.default.tokens_per_day": 50_000,
    },
    "relaxed": {
        "prompt_controls.semantic.block_threshold": 0.90,
        "prompt_controls.semantic.on_failure": "allow_and_flag",
        "prompt_controls.secrets.mode": "redact",
        "prompt_controls.pii.mode": "log",
        "prompt_controls.injection.mode": "log",
        "markers.denied": "[NOT AUTHORIZED]",
        "markers.rejected": UNAVAILABLE,
        "markers.empty": "[NO DATA]",
        "markers.error": UNAVAILABLE,
        "sql_controls.select_star": "expand",
        "output_controls.echo_own_input": True,
        "tool_controls.max_tool_iterations": 6,
        "budgets.default.tokens_per_day": 200_000,
    },
}
