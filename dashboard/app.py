"""Streamlit dashboard, auto-refresh. Spec section 12 'Dashboard panels'. Owner: Person 4.

    streamlit run dashboard/app.py          # gateway at ACL_GATEWAY_URL, default http://127.0.0.1:8000

Reads only the gateway's HTTP endpoints (/metrics, /policy/effective, /audit/export);
it never opens demo.db, state.db or the audit file. Panels: posture, live feed, totals,
export. The live panels refresh every ``dashboard.refresh_seconds`` (from
/policy/effective). If the gateway is down, a banner says so and the page keeps running.
"""
from __future__ import annotations

import os
from typing import Any

import httpx
import streamlit as st

GATEWAY_URL = os.environ.get("ACL_GATEWAY_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT_S = 2.0
DEFAULT_REFRESH_S = 2
PENDING = "pending"
DOWN = "down"


def fetch(path: str) -> tuple[Any, str | None]:
    """(JSON body, None) or (None, problem): ``down`` if unreachable, ``pending`` if the endpoint is missing."""
    try:
        r = httpx.get(GATEWAY_URL + path, timeout=TIMEOUT_S)
    except httpx.HTTPError:
        return None, DOWN
    if r.status_code == 404:
        return None, PENDING
    if r.status_code != 200:
        return None, "HTTP " + str(r.status_code)
    try:
        return r.json(), None
    except ValueError:
        return None, "unreadable response"


def export_csv() -> bytes:
    """The audit log as CSV, fetched only when the download button is clicked."""
    try:
        r = httpx.get(GATEWAY_URL + "/audit/export", params={"format": "csv"}, timeout=10.0)
    except httpx.HTTPError:
        r = None
    if r is None or r.status_code != 200:
        return b"error\nThe gateway could not be reached; no audit export was downloaded.\n"
    return r.content


def refresh_seconds(effective: Any) -> float:
    """``dashboard.refresh_seconds`` from /policy/effective; the default if unavailable."""
    try:
        value = float(effective["controls"]["dashboard.refresh_seconds"]["value"])
        return value if value > 0 else DEFAULT_REFRESH_S
    except (KeyError, TypeError, ValueError):
        return DEFAULT_REFRESH_S


def control_rows(effective: dict[str, Any]) -> list[dict[str, Any]]:
    """Posture table: one row per control with its value (mode) and source."""
    disabled = set(effective.get("disabled_controls") or [])
    rows = []
    for name, c in sorted((effective.get("controls") or {}).items()):
        value = c.get("value") if isinstance(c, dict) else c
        source = c.get("source") if isinstance(c, dict) else ""
        off = any(name == d or name.startswith(d + ".") for d in disabled)
        rows.append({"control": name, "mode": "off" if off else _cell(value), "source": source})
    return rows


def feed_rows(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """Live feed table from ``last_requests``; block reasons are the gateway's plain sentences."""
    return [
        {"time": r.get("time"), "user": r.get("user") or "(unauthenticated)", "role": r.get("role") or "",
         "verdict": r.get("verdict"), "control": r.get("control") or "", "reason": r.get("reason") or ""}
        for r in metrics.get("last_requests") or []
    ]


def totals(metrics: dict[str, Any]) -> dict[str, int]:
    verdicts = metrics.get("requests_by_verdict") or {}
    users = (metrics.get("tokens_and_cost_by_user") or {}).get("users") or {}
    return {
        "allowed": int(verdicts.get("allow", 0)),
        "blocked": int(verdicts.get("block", 0)),
        "redacted": int(verdicts.get("redact", 0)),
        "tokens today": sum(int(u.get("tokens", 0)) for u in users.values()),
    }


def _cell(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)
    return "" if value is None else str(value)


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------


def _banner(problem: str) -> None:
    if problem == DOWN:
        st.error("Gateway unreachable at " + GATEWAY_URL + ". Start it with `uvicorn gateway.main:app --port 8000`; "
                 "this page retries automatically.")
    else:
        st.warning("The gateway answered with an error (" + problem + "); retrying.")


def _posture(effective: Any, problem: str | None) -> None:
    st.subheader("Posture")
    if problem == PENDING:
        st.info("Policy view: pending (GET /policy/effective is not available yet).")
        return
    if problem is not None:
        st.caption("Policy view unavailable.")
        return
    a, b = st.columns(2)
    a.metric("Policy version", str(effective.get("version", ""))[:12])
    b.metric("Profile", str(effective.get("profile", "")))
    disabled = effective.get("disabled_controls") or []
    if disabled:
        st.error("Disabled controls: " + ", ".join(disabled))
    st.dataframe(control_rows(effective), hide_index=True, height=320)


def _live_feed(metrics: dict[str, Any]) -> None:
    st.subheader("Live feed")
    rows = feed_rows(metrics)
    if rows:
        st.dataframe(rows, hide_index=True)
    else:
        st.caption("No requests yet.")


def _totals(metrics: dict[str, Any]) -> None:
    st.subheader("Totals (today, UTC)")
    for column, (label, value) in zip(st.columns(4), totals(metrics).items()):
        column.metric(label.capitalize(), f"{value:,}")


def _export() -> None:
    st.subheader("Export")
    st.download_button("Download audit log (CSV)", data=export_csv, file_name="audit.csv", mime="text/csv",
                       on_click="ignore")


def main() -> None:
    st.set_page_config(page_title="AI Control Layer", layout="wide")
    st.title("AI Control Layer")
    effective, _ = fetch("/policy/effective")

    @st.fragment(run_every=refresh_seconds(effective))
    def live() -> None:
        effective, policy_problem = fetch("/policy/effective")
        metrics, metrics_problem = fetch("/metrics")
        problem = next((p for p in (metrics_problem, policy_problem) if p not in (None, PENDING)), None)
        if problem is not None:
            _banner(problem)
        _posture(effective, policy_problem)
        if metrics is None:
            st.caption("Metrics unavailable" + (" (pending)." if metrics_problem == PENDING else "."))
            return
        _live_feed(metrics)
        _totals(metrics)

    live()
    _export()


if __name__ == "__main__":
    main()
