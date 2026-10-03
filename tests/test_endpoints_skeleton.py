"""Every endpoint from spec section 13 exists and returns 501 until implemented. Owner: Person 4."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from gateway.main import app

client = TestClient(app)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/models"),
        ("GET", "/health"),
        ("GET", "/metrics"),
        ("GET", "/policy/effective"),
        ("POST", "/policy/reload"),
        ("GET", "/audit/export?format=csv"),
    ],
)
def test_endpoint_exists_and_is_not_implemented(method: str, path: str) -> None:
    assert client.request(method, path).status_code == 501


def test_chat_completions_exists_and_is_not_implemented() -> None:
    body = {"model": "llama3.2", "messages": [{"role": "user", "content": "hi"}]}
    r = client.post("/v1/chat/completions", json=body, headers={"Authorization": "Bearer demo-anna"})
    assert r.status_code == 501


def test_malformed_chat_request_error_does_not_echo_the_body() -> None:
    body = {"messages": [{"role": "user", "content": "my password is hunter2"}]}
    r = client.post("/v1/chat/completions", json=body)
    assert r.status_code == 422
    assert "hunter2" not in r.text
