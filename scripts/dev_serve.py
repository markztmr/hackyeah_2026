"""Dev launcher: run the real gateway before the inbound step is built. Owner: Person 4. NOT for the demo.

    ACL_DEV_SHIM=1 python scripts/dev_serve.py      # gateway on http://127.0.0.1:8000

Three pipeline steps are not built yet and raise NotImplementedError, so the plain
``uvicorn gateway.main:app`` answers every chat request with HTTP 500. This launcher
replaces only those three, reusing every inbound piece that does exist:

- ``inspect_inbound``: the real masker (``mask_messages`` + ``masking_decisions``) and the
  real tool-definition scan. Missing: history re-masking, so values from earlier answers
  in the history reach the model.
- ``judge``: allows everything (no semantic check; the phrase list and feed still run).
- ``record_issued``: does nothing.

Everything else (auth, budget, SQL checks, executor, fill, tool authorization, output
filter, audit) is the real code. Delete this file when inbound lands.
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
    """Steps 3a, 3b and 3d with the real code; 3c (history re-masking) is missing."""
    messages, vault, findings = mask_messages([m.model_dump(exclude_none=True) for m in req.messages], policy)
    tools = list(req.tools or [])
    decisions = masking_decisions(findings)
    if tools:
        decisions.append(scan_tool_definitions(tools, policy, _feed(policy)))
    return SanitizedRequest(messages=messages, tools=tools, findings=findings), vault, decisions


def judge(text: str, policy: Policy, *, models: Any = None) -> Decision:
    return Decision("input_checks", "semantic", "allow", "Judge not built (dev launcher).")


def record_issued(p: Principal, bindings: Any, cache: IssuedCache) -> None:
    return None


def install() -> None:
    """Replace the three unbuilt steps. Exits unless ACL_DEV_SHIM=1."""
    if os.environ.get(OPT_IN) != "1":
        sys.exit(f"Refusing to start: set {OPT_IN}=1. This launcher stubs the judge and history re-masking.")
    pipeline.inspect_inbound = inspect_inbound
    pipeline.judge = judge
    pipeline.record_issued = record_issued
    log.warning("DEV LAUNCHER: judge allows everything, history re-masking and issued-value recording are off. "
                "Not for the demo.")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    install()
    import uvicorn

    from gateway.main import app

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("ACL_PORT", "8000")))


if __name__ == "__main__":
    main()
