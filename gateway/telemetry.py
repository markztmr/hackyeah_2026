"""Per-step timers and latency summaries. Spec section 12 'Performance telemetry', section 13. Owner: Person 4.

Minimal version by Person 1 for the pipeline and /metrics.
"""
from __future__ import annotations

import math
import threading
import time
from collections import Counter, deque
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any


class StepTimer:
    """Wall-clock latency per pipeline step for one request, in milliseconds."""

    def __init__(self) -> None:
        self._start = time.perf_counter()
        self.steps: dict[str, float] = {}

    @contextmanager
    def step(self, name: str) -> Iterator[None]:
        """Time one step; also records the time when the step raises."""
        t = time.perf_counter()
        try:
            yield
        finally:
            self.steps[name] = self.steps.get(name, 0.0) + (time.perf_counter() - t) * 1000

    def total_ms(self) -> float:
        return (time.perf_counter() - self._start) * 1000


def _percentile(sorted_values: list[float], q: float) -> float:
    return sorted_values[max(0, math.ceil(q * len(sorted_values)) - 1)]


class Metrics:
    """Process-wide counters and latency windows for GET /metrics. Thread-safe; bounded memory."""

    def __init__(self, window: int = 1000) -> None:
        self._lock = threading.Lock()
        self._window = window
        self._verdicts: Counter[str] = Counter()
        self._steps: dict[str, deque[float]] = {}
        self._total: deque[float] = deque(maxlen=window)

    def record(self, verdict: str, steps: Mapping[str, float], total_ms: float) -> None:
        with self._lock:
            self._verdicts[verdict] += 1
            self._total.append(total_ms)
            for name, ms in steps.items():
                self._steps.setdefault(name, deque(maxlen=self._window)).append(ms)

    def snapshot(self) -> dict[str, Any]:
        def summary(values: deque[float]) -> dict[str, Any]:
            s = sorted(values)
            if not s:
                return {"count": 0, "median_ms": None, "p95_ms": None}
            return {"count": len(s), "median_ms": round(_percentile(s, 0.5), 3), "p95_ms": round(_percentile(s, 0.95), 3)}

        with self._lock:
            return {
                "requests": sum(self._verdicts.values()),
                "verdicts": dict(self._verdicts),
                "total": summary(self._total),
                "steps": {name: summary(v) for name, v in self._steps.items()},
            }
