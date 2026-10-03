"""FastAPI app and endpoints only; no business logic. Spec section 13 "Endpoints". Owner: Person 1."""
from __future__ import annotations

from typing import Literal

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from gateway.models import ChatRequest

app = FastAPI(title="AI Control Layer")


@app.exception_handler(RequestValidationError)
async def _invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
    """FastAPI's default 422 echoes the request body; never return client content (I8)."""
    return JSONResponse(status_code=422, content={"detail": "Invalid request body."})


def _not_implemented() -> JSONResponse:
    return JSONResponse(status_code=501, content={"detail": "Not implemented."})


@app.post("/v1/chat/completions")
def chat_completions(req: ChatRequest, authorization: str | None = Header(default=None)) -> JSONResponse:
    """OpenAI-compatible entry point. Spec section 4, section 13."""
    return _not_implemented()


@app.get("/v1/models")
def list_models() -> JSONResponse:
    """Allowed models, so stock clients can list them. Spec section 13."""
    return _not_implemented()


@app.get("/health")
def health() -> JSONResponse:
    """Liveness, policy and feed versions, model reachability, digest status. Spec section 13."""
    return _not_implemented()


@app.get("/metrics")
def metrics() -> JSONResponse:
    """Counters and latency summaries for the dashboard. Spec section 13."""
    return _not_implemented()


@app.get("/policy/effective")
def policy_effective() -> JSONResponse:
    """Every control with its value and source. Spec section 6, section 13."""
    return _not_implemented()


@app.post("/policy/reload")
def policy_reload() -> JSONResponse:
    """Manual reload of policy and feed. Spec section 6, section 13."""
    return _not_implemented()


@app.get("/audit/export")
def audit_export(format: Literal["csv"] = "csv") -> JSONResponse:
    """Audit export for security teams. Spec section 13."""
    return _not_implemented()
