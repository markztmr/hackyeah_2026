"""Streamlit dashboard, auto-refresh. Spec section 12 'Dashboard panels'. Owner: Person 4.

    streamlit run dashboard/app.py          # gateway at ACL_GATEWAY_URL, default http://127.0.0.1:8000

Reads only the gateway's HTTP endpoints (/metrics, /policy/effective, /health,
/audit/export); it never opens demo.db, state.db or the audit file. The seven panels of
section 12: posture, live feed, threats, data access, consumption, performance, export,
plus the T1 totals. The live panels refresh every ``dashboard.refresh_seconds`` (from
/policy/effective); /health (model pings and a fresh digest check, so slower) is cached
for ``HEALTH_TTL_S`` and refreshed in a background thread, so a refresh never stalls the
page. If the gateway is down, a banner says so and the page keeps running.

Made for a projector: large numbers, grey for everything except blocks and denials, which
use the one accent colour, and every panel at most one screen tall.
"""
from __future__ import annotations

import html
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import altair as alt
import httpx
import pandas as pd
import streamlit as st

GATEWAY_URL = os.environ.get("ACL_GATEWAY_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT_S = 2.0
HEALTH_TIMEOUT_S = 10.0
HEALTH_TTL_S = 30
DEFAULT_REFRESH_S = 2
PENDING = "pending"
DOWN = "down"
ACCENT = "#dc2626"  # blocks, denials, "off": the only colour that draws the eye
NEUTRAL = "#94a3b8"
DARK = "#334155"
PANEL_HEIGHT = 360  # px; tables and charts stay well inside one projector screen
BINDING_STATUSES = ("resolved", "denied", "rejected", "empty", "error")
CSS = f"""
<style>
header[data-testid="stHeader"] {{ background: transparent; }}
.block-container {{ padding-top: 2.2rem; max-width: 1600px; }}
.acl-hero {{ display: flex; align-items: center; gap: 1.1rem; padding: 1.4rem 1.8rem; margin-bottom: 1.2rem;
  border-radius: 1.1rem; color: #f8fafc; background: linear-gradient(120deg, #0f172a 0%, #1e293b 55%, #334155 100%);
  box-shadow: 0 10px 30px -12px rgba(15, 23, 42, .45); }}
.acl-hero svg {{ flex: none; }}
.acl-hero h1 {{ margin: 0; padding: 0; font-size: 2rem; font-weight: 800; letter-spacing: -.02em; color: #f8fafc; }}
.acl-hero p {{ margin: .15rem 0 0; color: #cbd5e1; font-size: 1rem; }}
.acl-hero .acl-url {{ margin-left: auto; padding: .35rem .8rem; border-radius: 999px; font-size: .85rem;
  background: rgba(148, 163, 184, .18); color: #e2e8f0; border: 1px solid rgba(148, 163, 184, .35); }}
[class*="st-key-panel_"] {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 1rem;
  padding: 1.1rem 1.3rem 1.3rem; box-shadow: 0 1px 2px rgba(15, 23, 42, .04), 0 8px 24px -16px rgba(15, 23, 42, .18); }}
[class*="st-key-panel_"] h3 {{ margin-top: 0; padding-top: 0; font-weight: 700; letter-spacing: -.01em; }}
[data-testid="stMetric"] {{ background: #ffffff; border-radius: .9rem; padding: 1rem 1.2rem;
  box-shadow: 0 1px 2px rgba(15, 23, 42, .04), 0 8px 24px -18px rgba(15, 23, 42, .25); }}
[data-testid="stMetricValue"] {{ font-size: 2.8rem; line-height: 1.1; font-weight: 800; letter-spacing: -.02em; }}
[data-testid="stMetricLabel"] p {{ font-size: .85rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: .06em; color: #64748b; }}
[class*="st-key-panel_posture"] [data-testid="stMetricValue"] {{ font-size: 1.6rem; }}
[class*="st-key-panel_"] [data-testid="stMetric"] {{ background: #f8fafc; box-shadow: none;
  border: 1px solid #e2e8f0; }}
.st-key-blocked_total [data-testid="stMetric"] {{ border-left: 5px solid {ACCENT}; }}
.st-key-blocked_total [data-testid="stMetricValue"] {{ color: {ACCENT}; }}
[data-testid="stCaptionContainer"] p {{ font-weight: 500; color: #64748b; }}
.acl-status {{ display: inline-flex; align-items: center; gap: .45rem; font-size: .9rem; color: #475569; }}
.acl-dot {{ width: .6rem; height: .6rem; border-radius: 50%; background: #22c55e;
  box-shadow: 0 0 0 4px rgba(34, 197, 94, .18); }}
.acl-dot.down {{ background: {ACCENT}; box-shadow: 0 0 0 4px rgba(220, 38, 38, .18); }}
.acl-dot:not(.down) {{ animation: acl-pulse 2.4s ease-in-out infinite; }}
@keyframes acl-pulse {{ 0%, 100% {{ box-shadow: 0 0 0 3px rgba(34, 197, 94, .22); }}
  50% {{ box-shadow: 0 0 0 6px rgba(34, 197, 94, .08); }} }}
/* Live refresh without flicker: the fragment reruns every few seconds, so Streamlit's
   "stale" dimming and the running indicator would blink on every tick. */
[data-testid="stElementContainer"][data-stale="true"], [data-stale="true"] {{ opacity: 1 !important;
  filter: none !important; transition: none !important; }}
[data-testid="stStatusWidget"] {{ visibility: hidden; }}
/* Element toolbars keep Search and Show/hide columns only; fullscreen (cropped to half a
   screen), per-element downloads and the chart developer actions go. The audit export
   button stays the one way to download. */
[data-testid="stElementToolbarButton"]:has(button[aria-label^="Fullscreen"]),
[data-testid="stElementToolbarButton"]:has(button[aria-label^="Download"]),
[data-testid="stElementToolbarButton"]:has(button[aria-label^="Show data"]),
[data-testid="stElementToolbarButton"]:has(button[aria-label^="Copy Vega-Lite"]) {{ display: none; }}
[class*="st-key-panel_"], [data-testid="stMetric"] {{ transition: box-shadow .25s ease, transform .25s ease; }}
[class*="st-key-panel_"]:hover {{ box-shadow: 0 1px 2px rgba(15, 23, 42, .05), 0 14px 32px -18px rgba(15, 23, 42, .28); }}
[data-testid="stMetric"]:hover {{ transform: translateY(-1px); }}
.acl-chart-empty {{ display: flex; align-items: center; justify-content: center; height: 120px;
  border: 1px dashed #e2e8f0; border-radius: .75rem; color: #94a3b8; font-size: .9rem; }}
</style>
"""
SHIELD = ('<svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="#e2e8f0" stroke-width="1.8" '
          'stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6z"/>'
          '<path d="M9 12l2 2 4-4"/></svg>')


def fetch(path: str, timeout: float = TIMEOUT_S) -> tuple[Any, str | None]:
    """(JSON body, None) or (None, problem): ``down`` if unreachable, ``pending`` if the endpoint is missing."""
    try:
        r = httpx.get(GATEWAY_URL + path, timeout=timeout)
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


@dataclass
class HealthCache:
    """The last /health answer of one browser session, refreshed in the background.

    /health pings both models and re-checks digests, which takes seconds. Fetching it
    inline every ``HEALTH_TTL_S`` froze the live fragment for that long. Only the very
    first fetch waits; after that a stale value is served while a thread fetches the next.
    """

    value: tuple[Any, str | None] | None = None
    fetched_at: float = 0.0
    busy: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    def get(self, now: float | None = None) -> tuple[Any, str | None]:
        now = time.monotonic() if now is None else now
        if self.value is None:
            self._refresh()
            return self.value or (None, DOWN)
        with self.lock:
            start = not self.busy and now - self.fetched_at >= HEALTH_TTL_S
            if start:
                self.busy = True
        if start:
            threading.Thread(target=self._refresh, daemon=True).start()
        return self.value

    def _refresh(self) -> None:
        try:
            result = fetch("/health", HEALTH_TIMEOUT_S)
        except Exception:  # noqa: BLE001 - keep serving the last value
            result = self.value or (None, DOWN)
        with self.lock:
            self.value, self.fetched_at, self.busy = result, time.monotonic(), False


def fetch_health() -> tuple[Any, str | None]:
    """/health for this session, without blocking a refresh (see ``HealthCache``)."""
    # Not isinstance: every rerun re-executes this file, so the class object is new each time.
    cache = st.session_state.get("health_cache")
    if cache is None:
        cache = st.session_state["health_cache"] = HealthCache()
    return cache.get()


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


# ---------------------------------------------------------------------------
# Rows for each panel (pure functions, tested without Streamlit)
# ---------------------------------------------------------------------------


def control_rows(effective: dict[str, Any]) -> list[dict[str, Any]]:
    """Posture table: one row per control with its value (mode) and source (explicit, profile, default)."""
    disabled = set(effective.get("disabled_controls") or [])
    rows = []
    for name, c in sorted((effective.get("controls") or {}).items()):
        value = c.get("value") if isinstance(c, dict) else c
        source = c.get("source") if isinstance(c, dict) else ""
        off = any(name == d or name.startswith(d + ".") for d in disabled)
        rows.append({"control": name, "mode": "off" if off else _cell(value), "source": source})
    return rows


def posture_status(health: Any) -> dict[str, Any]:
    """Feed version, digest summary and last reload errors from /health; placeholders if unavailable."""
    if not isinstance(health, dict):
        return {"feed": "unknown", "digests": "unknown", "digests_ok": None, "blocked_models": [], "errors": []}
    digests = health.get("digests") or {}
    models = digests.get("models") or {}
    blocked = sorted(n for n, d in models.items() if (d or {}).get("status") not in ("ok", "unpinned"))
    if not digests.get("checked"):
        summary, ok = "not checked", None
    elif blocked:
        summary, ok = f"{len(blocked)} blocked", False
    else:
        summary, ok = f"{len(models)} ok", True
    errors = []
    for part, label in (("policy", "Policy"), ("feed", "Signature feed")):
        error = (health.get(part) or {}).get("error")
        if error:
            errors.append(f"{label} reload rejected, last valid version kept: {error}")
    return {"feed": str((health.get("feed") or {}).get("version") or "unknown"), "digests": summary,
            "digests_ok": ok, "blocked_models": blocked, "errors": errors}


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


def over_time_rows(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """Per-minute requests and blocks for the last hour, minute shown as HH:MM (UTC)."""
    return [{"minute": str(b.get("minute", ""))[11:16], "requests": int(b.get("requests", 0)),
             "blocks": int(b.get("blocks", 0))} for b in metrics.get("blocks_over_time") or []]


def count_rows(counts: Any, key: str) -> list[dict[str, Any]]:
    """``{name: n}`` as rows, largest first."""
    items = counts.items() if isinstance(counts, dict) else []
    return [{key: k, "blocks": int(v)} for k, v in sorted(items, key=lambda kv: (-int(kv[1]), kv[0]))]


def binding_rows(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per role and table with a column per binding outcome."""
    rows = []
    for role, tables in sorted((metrics.get("binding_outcomes_by_role_and_table") or {}).items()):
        for table, counts in sorted(tables.items()):
            rows.append({"role": role, "table": table, **{s: int(counts.get(s, 0)) for s in BINDING_STATUSES}})
    return rows


def tool_rows(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"tool": tool, "allowed": int(c.get("allow", 0)), "denied": int(c.get("deny", 0))}
            for tool, c in sorted((metrics.get("tool_decisions_by_tool") or {}).items())]


def budget_rows(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """Tokens and cost per user against the user's daily budget; fractions capped at 1 for the bars."""
    rows = []
    for user, u in sorted(((metrics.get("tokens_and_cost_by_user") or {}).get("users") or {}).items()):
        limits = u.get("limits") or {}
        tokens, cost = int(u.get("tokens", 0)), float(u.get("cost_usd", 0.0))
        token_limit, cost_limit = limits.get("tokens_per_day"), limits.get("cost_per_day_usd")
        rows.append({
            "user": user, "role": u.get("role") or "", "tokens": tokens, "token_limit": token_limit,
            "token_share": min(1.0, tokens / token_limit) if token_limit else 0.0,
            "cost_usd": cost, "cost_limit": cost_limit,
            "cost_share": min(1.0, cost / cost_limit) if cost_limit else 0.0,
        })
    return rows


def latency_rows(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"step": step, "median ms": float(v.get("median_ms", 0.0)), "p95 ms": float(v.get("p95_ms", 0.0)),
             "requests": int(v.get("count", 0))}
            for step, v in (metrics.get("latency_by_step") or {}).items()]


def format_ms(ms: float) -> str:
    """Latency for people: "0.42 ms", "13.1 ms", "6.96 s"."""
    return f"{ms / 1000:.3g} s" if ms >= 1000 else f"{ms:.3g} ms"


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


def _red_off(value: Any) -> str:
    return f"color: {ACCENT}; font-weight: 700" if value == "off" else ""


def _verdict_style(value: Any) -> str:
    """Blocks in the accent colour; every other verdict stays grey."""
    return f"color: {ACCENT}; font-weight: 700" if value == "block" else "color: #64748b; font-weight: 600"


def _hero() -> None:
    st.markdown(
        '<div class="acl-hero">' + SHIELD + '<div><h1>AI Control Layer</h1>'
        "<p>Security gateway for every model call: posture, threats, data access and cost, live.</p></div>"
        '<span class="acl-url">' + html.escape(GATEWAY_URL) + "</span></div>",
        unsafe_allow_html=True)


def _status(problem: str | None, refresh: float) -> None:
    if problem is None:
        text, dot = f"Live · refreshes every {refresh:g} s", "acl-dot"
    else:
        text, dot = "Gateway unavailable · retrying", "acl-dot down"
    st.markdown(f'<span class="acl-status"><span class="{dot}"></span>{text}</span>', unsafe_allow_html=True)


def _posture(effective: Any, problem: str | None, health: Any) -> None:
    st.subheader("Posture")
    if problem == PENDING:
        st.info("Policy view: pending (GET /policy/effective is not available yet).")
        return
    if problem is not None:
        st.caption("Policy view unavailable.")
        return
    status = posture_status(health)
    a, b, c, d = st.columns(4)
    a.metric("Policy version", str(effective.get("version", ""))[:12])
    b.metric("Profile", str(effective.get("profile", "")))
    c.metric("Signature feed", status["feed"])
    d.metric("Model digests", status["digests"])
    for error in status["errors"]:
        st.error(error)
    if status["blocked_models"]:
        st.error("Models blocked by digest pinning: " + ", ".join(status["blocked_models"]))
    disabled = effective.get("disabled_controls") or []
    if disabled:
        st.error("Disabled controls: " + ", ".join(disabled))
    rows = control_rows(effective)
    table = pd.DataFrame(rows, columns=["control", "mode", "source"]).style.map(_red_off, subset=["mode"])
    st.dataframe(table, hide_index=True, height=PANEL_HEIGHT, use_container_width=True)


def _totals(metrics: dict[str, Any]) -> None:
    st.subheader("Totals (today, UTC)")
    for column, (label, value) in zip(st.columns(4), totals(metrics).items()):
        with column.container(key="blocked_total" if label == "blocked" else None):
            st.metric(label.capitalize(), f"{value:,}")


def _live_feed(metrics: dict[str, Any]) -> None:
    st.subheader("Live feed")
    rows = feed_rows(metrics)
    if rows:
        shown = [{**r, "time": str(r["time"] or "")[11:19]} for r in rows]  # HH:MM:SS (UTC)
        table = pd.DataFrame(shown).style.map(_verdict_style, subset=["verdict"])
        st.dataframe(table, hide_index=True, height=min(PANEL_HEIGHT, 38 + 35 * len(rows)), use_container_width=True)
    else:
        st.caption("No requests yet.")


# ---------------------------------------------------------------------------
# Charts (Altair, one shared style: quiet axes, value labels, tooltips)
# ---------------------------------------------------------------------------

FONT = "Inter, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
INK = "#0f172a"
MUTED = "#64748b"
GRID = "#eef1f6"
LATENCY_STEPS = ("median ms", "p95 ms")


def _rgba(hex_color: str, alpha: float) -> str:
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return f"rgba({r}, {g}, {b}, {alpha})"


def _style(chart: Any, height: int) -> Any:
    return (chart.properties(height=height, width="container")
            .configure(font=FONT, background="transparent", padding={"left": 2, "right": 8, "top": 6, "bottom": 2})
            .configure_view(strokeWidth=0)
            .configure_axis(labelColor=MUTED, labelFontSize=12, labelPadding=6, title=None, domain=False,
                            ticks=False, gridColor=GRID)
            .configure_legend(orient="top", direction="horizontal", title=None, labelColor=MUTED, labelFontSize=12,
                              symbolType="circle", symbolSize=80, padding=0, offset=6)
            .configure_text(font=FONT))


def _show_chart(where: Any, chart: Any, key: str) -> None:
    where.altair_chart(chart, width="stretch", theme=None, key=key)


def _empty(where: Any, text: str) -> None:
    where.markdown(f'<div class="acl-chart-empty">{html.escape(text)}</div>', unsafe_allow_html=True)


BAR_PX = 18  # bar thickness for category charts; the chart is only as tall as its rows
ROW_PX = 34


def _rows_height(count: int, height: int) -> int:
    """Category charts grow with their rows (up to ``height``) instead of stretching a few bars."""
    return min(height, ROW_PX * max(count, 1) + 30)


def timeline_chart(metrics: dict[str, Any], y: str, color: str, height: int) -> Any | None:
    """Per-minute counts for the last hour as UTC minute columns, highlighted on hover."""
    buckets = metrics.get("blocks_over_time") or []
    if not buckets:
        return None
    df = pd.DataFrame({"time": pd.to_datetime([b.get("minute") for b in buckets], utc=True),
                       "value": [int(b.get(y, 0)) for b in buckets]})
    hover = alt.selection_point(fields=["time"], on="pointerover", clear="pointerout", empty=False)
    bars = alt.Chart(df).mark_bar(color=color, cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
        # utc* time unit: bins and labels in UTC, as the caption says, whatever the viewer's time zone
        x=alt.X("utchoursminutes(time):T", axis=alt.Axis(format="%H:%M", tickCount=6, grid=False, labelFlush=False),
                scale=alt.Scale(paddingInner=0.25)),
        y=alt.Y("value:Q", scale=alt.Scale(domainMin=0, nice=True),
                axis=alt.Axis(tickMinStep=1, format="d", tickCount=4, gridDash=[3, 3])),
        opacity=alt.condition(hover, alt.value(1), alt.value(0.78)),
        tooltip=[alt.Tooltip("utchoursminutes(time):T", title="Minute (UTC)", format="%H:%M"),
                 alt.Tooltip("value:Q", title=y.capitalize())],
    ).add_params(hover)
    return _style(bars, height)


def rank_chart(rows: list[dict[str, Any]], key: str, color: str, height: int) -> Any:
    """Horizontal bars, largest first, with the count printed at the end of each bar."""
    df = pd.DataFrame(rows)
    top = max(int(df["blocks"].max()), 1)
    base = alt.Chart(df).encode(
        y=alt.Y(f"{key}:N", sort="-x", axis=alt.Axis(labelLimit=170, labelColor=INK, labelFontSize=12.5)),
        x=alt.X("blocks:Q", axis=None, scale=alt.Scale(domain=[0, top * 1.22], nice=False)),
        tooltip=[alt.Tooltip(f"{key}:N", title=key.capitalize()), alt.Tooltip("blocks:Q", title="Blocks")])
    bars = base.mark_bar(color=color, cornerRadiusEnd=5, size=BAR_PX)
    labels = base.mark_text(align="left", dx=6, color=INK, fontWeight=600, fontSize=12.5).encode(text="blocks:Q")
    return _style(bars + labels, _rows_height(len(rows), height))


def tools_chart(rows: list[dict[str, Any]], height: int) -> Any:
    """Allowed and denied calls per client tool, stacked, with a legend on top."""
    df = pd.DataFrame(rows).melt(id_vars="tool", value_vars=["allowed", "denied"], var_name="outcome",
                                 value_name="calls")
    df = df[df["calls"] > 0]
    totals_df = pd.DataFrame([{"tool": r["tool"], "total": r["allowed"] + r["denied"]} for r in rows])
    top = max(int(totals_df["total"].max()), 1)
    y = alt.Y("tool:N", axis=alt.Axis(labelColor=INK, labelFontSize=12.5, labelLimit=170))
    x_scale = alt.Scale(domain=[0, top * 1.22], nice=False)
    bars = alt.Chart(df).mark_bar(cornerRadius=4, size=BAR_PX, stroke="#ffffff", strokeWidth=1.5).encode(
        y=y, x=alt.X("calls:Q", stack="zero", scale=x_scale, axis=None),
        color=alt.Color("outcome:N", scale=alt.Scale(domain=["allowed", "denied"], range=[NEUTRAL, ACCENT])),
        order=alt.Order("outcome:N", sort="ascending"),
        tooltip=[alt.Tooltip("tool:N", title="Tool"), alt.Tooltip("outcome:N", title="Outcome"),
                 alt.Tooltip("calls:Q", title="Calls")])
    labels = alt.Chart(totals_df).mark_text(align="left", dx=6, color=INK, fontWeight=600, fontSize=12.5).encode(
        y=y, x=alt.X("total:Q", scale=x_scale), text="total:Q")
    return _style(bars + labels, _rows_height(len(rows), height) + 24)  # + the legend row


# Steps range from microseconds (fill) to seconds (model calls), so the axis is logarithmic;
# a floor keeps 0 ms readings on the chart. Labels read as "0.1 ms", "15 ms", "6.9 s".
LATENCY_FLOOR_MS = 0.001
LATENCY_TICKS = [0.001, 0.01, 0.1, 1, 10, 100, 1000, 10000, 100000]
_MS_LABEL = ("{v} >= 1000 ? format({v} / 1000, '.3~r') + ' s' : format({v}, '.3~r') + ' ms'")


def latency_chart(rows: list[dict[str, Any]], height: int) -> Any:
    """Median to p95 per pipeline step as a dumbbell on a log axis: the gap is the tail latency."""
    steps = [{**r, "median ms": max(r["median ms"], LATENCY_FLOOR_MS), "p95 ms": max(r["p95 ms"], LATENCY_FLOOR_MS)}
             for r in rows if r["step"] != "total"]
    df = pd.DataFrame(steps)
    order = [r["step"] for r in steps]
    long = df.melt(id_vars="step", value_vars=list(LATENCY_STEPS), var_name="measure", value_name="ms")
    top = max(float(df["p95 ms"].max()), 1.0)
    ticks = [t for t in LATENCY_TICKS if t <= top * 10]
    scale = alt.Scale(type="log", domain=[LATENCY_FLOOR_MS, top * 8], nice=False)
    y = alt.Y("step:N", sort=order, axis=alt.Axis(labelColor=INK, labelFontSize=12.5, labelLimit=170))
    x = alt.X("ms:Q", scale=scale, axis=alt.Axis(values=ticks, gridDash=[3, 3],
                                                 labelExpr=_MS_LABEL.format(v="datum.value")))
    span = alt.Chart(df).mark_rule(color="#cbd5e1", strokeWidth=3, strokeCap="round").encode(
        y=y, x=alt.X("median ms:Q", scale=scale), x2="p95 ms:Q")
    dots = alt.Chart(long).mark_circle(size=110, opacity=1, stroke="#ffffff", strokeWidth=1.5).encode(
        y=y, x=x,
        color=alt.Color("measure:N", scale=alt.Scale(domain=list(LATENCY_STEPS), range=[NEUTRAL, DARK]),
                        legend=alt.Legend(labelExpr="datum.label == 'median ms' ? 'Median' : 'p95'")),
        tooltip=[alt.Tooltip("step:N", title="Step"), alt.Tooltip("measure:N", title="Measure"),
                 alt.Tooltip("ms:Q", title="Latency (ms)", format=".3f")])
    labels = alt.Chart(df).transform_calculate(label=_MS_LABEL.format(v="datum['p95 ms']")).mark_text(
        align="left", dx=10, color=MUTED, fontSize=12).encode(y=y, x=alt.X("p95 ms:Q", scale=scale), text="label:N")
    return _style(span + dots + labels, height)


def _minute_chart(where: Any, metrics: dict[str, Any], y: str, color: str, height: int) -> None:
    chart = timeline_chart(metrics, y, color, height)
    if chart is None:
        _empty(where, "No data yet")
    else:
        _show_chart(where, chart, "chart_minutes_" + y)


def _threats(metrics: dict[str, Any]) -> None:
    st.subheader("Threats")
    st.caption("Blocks per minute, last hour (UTC)")
    _minute_chart(st, metrics, "blocks", ACCENT, 220)
    by_control, by_category, by_user = st.columns(3)
    for column, title, counts, key in (
        (by_control, "By control (today)", metrics.get("blocks_by_control"), "control"),
        (by_category, "By signature category (today)", metrics.get("blocks_by_signature_category"), "category"),
        (by_user, "Top users by blocks (today)", metrics.get("blocks_by_user"), "user"),
    ):
        column.caption(title)
        rows = count_rows(counts, key)[:8]
        if rows:
            _show_chart(column, rank_chart(rows, key, ACCENT, 240), "chart_rank_" + key)
        else:
            _empty(column, "No blocks")


def _data_access(metrics: dict[str, Any]) -> None:
    st.subheader("Data access (today)")
    bindings, tools = st.columns([3, 2])
    bindings.caption("query_data outcomes by role and table")
    rows = binding_rows(metrics)
    if rows:
        bindings.dataframe(rows, hide_index=True, height=min(PANEL_HEIGHT, 38 + 35 * len(rows)),
                           use_container_width=True)
    else:
        bindings.markdown("**No queries yet**")
    tools.caption("Client tool calls: allowed vs denied")
    rows = tool_rows(metrics)
    if rows:
        _show_chart(tools, tools_chart(rows, 240), "chart_tools")
    else:
        _empty(tools, "No tool calls yet")


def _consumption(metrics: dict[str, Any]) -> None:
    st.subheader("Consumption (today, UTC)")
    users, rate = st.columns([3, 2])
    rows = budget_rows(metrics)
    if not rows:
        users.markdown("**No usage yet**")
    for r in rows:
        token_limit = f"{int(r['token_limit']):,}" if r["token_limit"] else "?"
        cost_limit = f"\\${float(r['cost_limit']):.2f}" if r["cost_limit"] else "?"  # \\$: not LaTeX
        users.markdown(f"**{r['user']}** ({r['role']})")
        users.progress(r["token_share"], text=f"{r['tokens']:,} / {token_limit} tokens")
        users.progress(r["cost_share"], text=f"\\${r['cost_usd']:.4f} / {cost_limit}")
    rate.caption("Requests per minute, last hour (UTC)")
    _minute_chart(rate, metrics, "requests", NEUTRAL, 240)


def _performance(metrics: dict[str, Any]) -> None:
    st.subheader("Performance (today)")
    rows = latency_rows(metrics)
    if not rows:
        st.markdown("**No requests yet**")
        return
    table, chart = st.columns([2, 3])
    table.dataframe(rows, hide_index=True, height=min(PANEL_HEIGHT, 38 + 35 * len(rows)), use_container_width=True)
    total = next((r for r in rows if r["step"] == "total"), None)
    if total:
        chart.caption(f"Per step, median to p95 · whole request: {format_ms(total['median ms'])} median, "
                      f"{format_ms(total['p95 ms'])} p95")
    if any(r["step"] != "total" for r in rows):
        _show_chart(chart, latency_chart(rows, PANEL_HEIGHT - 40), "chart_latency")


def _export() -> None:
    st.subheader("Export")
    st.download_button("Download audit log (CSV)", data=export_csv, file_name="audit.csv", mime="text/csv",
                       on_click="ignore")


def main() -> None:
    st.set_page_config(page_title="AI Control Layer", page_icon=":material/shield:", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    _hero()
    effective, _ = fetch("/policy/effective")
    refresh = refresh_seconds(effective)

    @st.fragment(run_every=refresh)
    def live() -> None:
        effective, policy_problem = fetch("/policy/effective")
        metrics, metrics_problem = fetch("/metrics")
        health, _ = fetch_health()
        problem = next((p for p in (metrics_problem, policy_problem) if p not in (None, PENDING)), None)
        _status(problem, refresh)
        if problem is not None:
            _banner(problem)
        if metrics is not None:
            _totals(metrics)
        with st.container(key="panel_posture"):
            _posture(effective, policy_problem, health)
        if metrics is None:
            st.caption("Metrics unavailable" + (" (pending)." if metrics_problem == PENDING else "."))
            return
        with st.container(key="panel_feed"):
            _live_feed(metrics)
        with st.container(key="panel_threats"):
            _threats(metrics)
        with st.container(key="panel_data"):
            _data_access(metrics)
        with st.container(key="panel_consumption"):
            _consumption(metrics)
        with st.container(key="panel_performance"):
            _performance(metrics)

    live()
    with st.container(key="panel_export"):
        _export()


if __name__ == "__main__":
    main()
