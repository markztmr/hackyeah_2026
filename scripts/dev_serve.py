"""Dev launcher: run the real gateway before the inbound step is built. Owner: Person 4. NOT for the demo.

    ACL_DEV_SHIM=1 python scripts/dev_serve.py      # gateway on http://127.0.0.1:8000

One pipeline step is not built yet and raises NotImplementedError, so the plain
``uvicorn gateway.main:app`` answers every chat request with HTTP 500. This launcher
replaces only ``inspect_inbound``, assembled from the real pieces: the masker
(``mask_messages`` + ``masking_decisions``), history re-masking and the tool-definition
scan.

Everything else (auth, budget, judge, SQL checks, executor, disclosure, fill, issued
values, tool authorization, output filter, audit) is the real code. Delete this file
when ``inspect_inbound`` lands.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from gateway import pipeline  # noqa: E402
from gateway.inbound.history import remask_history  # noqa: E402
from gateway.inbound.injection import scan_tool_definitions  # noqa: E402
from gateway.inbound.masker import mask_messages, masking_decisions  # noqa: E402
from gateway.inbound.signatures import FeedStore  # noqa: E402
from gateway.models import ChatRequest, Decision, IssuedCache, Policy, Principal, SanitizedRequest, Vault  # noqa: E402
from gateway.policy.loader import policy_path, setting  # noqa: E402

log = logging.getLogger("dev_serve")
OPT_IN = "ACL_DEV_SHIM"
_feeds: dict[Path, FeedStore] = {}


def _feed(policy: Policy) -> Any:
    path = Path(setting(policy, "prompt_controls.signatures.feed"))
    if not path.is_absolute():
        path = policy_path().parent / path
    return _feeds.setdefault(path, FeedStore(path)).snapshot()


def inspect_inbound(
    req: ChatRequest, p: Principal, policy: Policy, cache: IssuedCache
) -> tuple[SanitizedRequest, Vault, list[Decision]]:
    """Steps 3a-3d with the real pieces."""
    messages, _ = remask_history([m.model_dump(exclude_none=True) for m in req.messages], p, cache, policy)
    messages, vault, findings = mask_messages(messages, policy)
    tools = list(req.tools or [])
    decisions = masking_decisions(findings)
    if tools:
        decisions.append(scan_tool_definitions(tools, policy, _feed(policy)))
    return SanitizedRequest(messages=messages, tools=tools, findings=findings), vault, decisions


def install() -> None:
    """Replace the unbuilt inbound step. Exits unless ACL_DEV_SHIM=1."""
    if os.environ.get(OPT_IN) != "1":
        sys.exit(f"Refusing to start: set {OPT_IN}=1. This launcher stands in for inspect_inbound.")
    pipeline.inspect_inbound = inspect_inbound
    log.warning("DEV LAUNCHER: inspect_inbound is assembled from its parts. Not for the demo.")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    install()
    import uvicorn

    from gateway.main import app

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("ACL_PORT", "8000")))


if __name__ == "__main__":
    main()
