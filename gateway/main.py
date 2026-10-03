"""FastAPI app and endpoints only; no business logic. Spec section 13 "Endpoints". Owner: Person 1.

Process state lives on ``app.state`` and is created at startup: the policy and feed
stores (startup fails if either file is invalid), the issued-value cache and metrics.
"""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response

from gateway import audit
from gateway.auth import AuthError, authenticate
from gateway.inbound.signatures import FeedStore
from gateway.llm import client as llm
from gateway.models import ChatRequest, IssuedCache, Policy, SignatureFeed
from gateway.pipeline import GatewayError, audit_rejected_request, run_pipeline
from gateway.policy.loader import PolicyStore, effective_policy, policy_path, setting
from gateway.telemetry import Metrics

log = logging.getLogger(__name__)
CHAT_PATH = "/v1/chat/completions"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.policy_store = PolicyStore(policy_path())
    app.state.feed_stores = {}
    app.state.cache = IssuedCache()
    app.state.metrics = Metrics()
    _feed_store(app, app.state.policy_store.snapshot())  # an invalid feed also stops startup
    yield


app = FastAPI(title="AI Control Layer", lifespan=lifespan)


def _policy_store(app: FastAPI) -> PolicyStore:
    return app.state.policy_store


def _feed_store(app: FastAPI, policy: Policy) -> FeedStore:
    """The feed named by ``prompt_controls.signatures.feed``, relative to the policy file."""
    path = Path(setting(policy, "prompt_controls.signatures.feed"))
    if not path.is_absolute():
        path = _policy_store(app).path.parent / path
    stores: dict[Path, FeedStore] = app.state.feed_stores
    if path not in stores:
        stores[path] = FeedStore(path)
    return stores[path]


def _snapshots(app: FastAPI) -> tuple[Policy, SignatureFeed]:
    """Policy and feed for one request, taken once (I16)."""
    policy = _policy_store(app).snapshot()
    return policy, _feed_store(app, policy).snapshot()


def _bearer_key(authorization: str | None) -> str:
    """The key from ``Authorization: Bearer <key>``; empty if missing or malformed (authentication then fails)."""
    scheme, _, key = (authorization or "").partition(" ")
    return key.strip() if scheme.lower() == "bearer" else ""


# ---------------------------------------------------------------------------
# Error handlers: fixed bodies, never client content, values or stack traces (I8)
# ---------------------------------------------------------------------------


@app.exception_handler(AuthError)
async def _unauthorized(request: Request, exc: AuthError) -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"error": {"message": "Invalid or missing API key.", "type": "authentication_error"}},
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.exception_handler(RequestValidationError)
async def _invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
    """FastAPI's default 422 echoes the request body. Chat requests still get their one audit record (I12)."""
    headers: dict[str, str] = {}
    if request.url.path == CHAT_PATH:
        policy, feed = _snapshots(request.app)
        headers["x-acl-request-id"] = audit_rejected_request(policy, feed, "Invalid request body.", request.app.state.metrics)
    return JSONResponse(status_code=422, content={"detail": "Invalid request body."}, headers=headers)


@app.exception_handler(GatewayError)
async def _gateway_error(request: Request, exc: GatewayError) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={"error": {"message": "Internal gateway error.", "type": "gateway_error", "request_id": exc.request_id}},
        headers={"x-acl-request-id": exc.request_id},
    )


@app.exception_handler(Exception)
async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
    log.error("Unhandled %s on %s", type(exc).__name__, request.url.path)
    return JSONResponse(status_code=500, content={"error": {"message": "Internal gateway error.", "type": "gateway_error"}})


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post(CHAT_PATH)
def chat_completions(request: Request, req: ChatRequest, authorization: str | None = Header(default=None)) -> JSONResponse:
    """OpenAI-compatible entry point. Spec section 4, section 13."""
    policy, feed = _snapshots(request.app)
    response, verdict = run_pipeline(
        _bearer_key(authorization), req, policy, feed, request.app.state.cache, metrics=request.app.state.metrics,
    )
    return JSONResponse(
        content=response.model_dump(exclude_none=True),
        headers={"x-acl-verdict": verdict, "x-acl-request-id": response.id},
    )


@app.get("/v1/models")
def list_models(request: Request, authorization: str | None = Header(default=None)) -> JSONResponse:
    """Allowed models, so stock clients can list them. Needs a valid key. Spec section 13."""
    policy = _policy_store(request.app).snapshot()
    authenticate(_bearer_key(authorization), policy)
    data = [{"id": m["name"], "object": "model", "created": 0, "owned_by": "ai-control-layer"}
            for m in setting(policy, "models.allowed")]
    return JSONResponse({"object": "list", "data": data})


@app.get("/health")
def health(request: Request) -> JSONResponse:
    """Liveness, policy and feed versions, model reachability, last reload errors. Spec section 13."""
    policy, _ = _snapshots(request.app)
    policy_status = _policy_store(request.app).status()
    feed_status = _feed_store(request.app, policy).status()
    models: dict[str, Any] = {}
    for purpose in ("answer", "judge"):
        models[purpose] = {
            "name": setting(policy, f"models.{purpose}.name"),
            "base_url": setting(policy, f"models.{purpose}.base_url"),
            "reachable": llm.ping(purpose, policy),
        }
    healthy = not policy_status["error"] and not feed_status["error"] and all(m["reachable"] for m in models.values())
    return JSONResponse({
        "status": "ok" if healthy else "degraded",
        "policy": policy_status,
        "feed": feed_status,
        "models": models,
        "digests": {"checked": False, "detail": "Digest pinning is not implemented yet."},
    })


@app.get("/metrics")
def metrics(request: Request) -> JSONResponse:
    """Dashboard sections computed from the audit log. Spec section 12 'Dashboard panels', section 13."""
    policy = _policy_store(request.app).snapshot()
    return JSONResponse(audit.audit_metrics(audit.read_audit(policy), policy))


@app.get("/policy/effective")
def policy_effective(request: Request) -> JSONResponse:
    """Every control with its value and source. Spec section 6, section 13."""
    return JSONResponse(effective_policy(_policy_store(request.app).snapshot()))


@app.post("/policy/reload")
def policy_reload(request: Request) -> JSONResponse:
    """Manual reload of policy and feed; 422 with the validation error if either is invalid. Spec section 6, 13."""
    policy_status = _policy_store(request.app).reload()
    feed_status = _feed_store(request.app, _policy_store(request.app).snapshot()).reload()
    ok = not policy_status["error"] and not feed_status["error"]
    return JSONResponse({"ok": ok, "policy": policy_status, "feed": feed_status}, status_code=200 if ok else 422)


def _utc(ts: datetime | None) -> datetime | None:
    return ts.replace(tzinfo=timezone.utc) if ts is not None and ts.tzinfo is None else ts


@app.get("/audit/export")
def audit_export(
    request: Request,
    format: Literal["csv"] = "csv",  # noqa: A002 - query parameter name from the spec
    since: datetime | None = None,
    until: datetime | None = None,
) -> Response:
    """Audit export for security teams, optionally for a time range. Spec section 13."""
    policy = _policy_store(request.app).snapshot()
    records = audit.read_audit(policy, _utc(since), _utc(until))
    return Response(
        audit.export_csv(records),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="audit.csv"'},
    )
