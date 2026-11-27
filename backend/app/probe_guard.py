"""Concurrency / dedup / rate-limit guard for probe endpoints (M-31).

Diagnosis and speedtest endpoints fire outbound probes; without a
guard one client can stack unlimited probes and exhaust the box.
Three mechanisms, all in-memory and per-process:

* Concurrency — at most :data:`PROBE_MAX_CONCURRENT` probe tasks
  run at once (across link-check, exit-ip and node speedtests).
  A further request gets 429 instead of queueing: a probe that
  waits behind a slow probe is indistinguishable from a hung probe.
  Note this counts *requests*, not the probes inside one request:
  ``speedtest-all`` still fans out to its locked 5-worker pool
  internally — that policy is untouched.
* Dedup — the same probe target within :data:`PROBE_DEDUP_TTL_S`
  reuses the previous result instead of probing again. Only pure
  reads are deduped (link-check, exit-ip): node speedtests are
  state-changing measurements (each run updates failure counters
  and ``last_delay_at``), so caching their result would falsify
  the health data — they get the concurrency cap and the rate
  limit, but never a cached result.
* Rate limit — :data:`PROBE_RATE_LIMIT` probe requests per
  :data:`PROBE_RATE_WINDOW_S` per client IP (sliding window).
  Route-check is not rate-limited: it is a local rule match with
  no outbound probe.

Tests reset the singleton via :func:`reset_probe_guard` (and
monkeypatch the module constants for the rate-limit test).
"""

from __future__ import annotations

import copy
import threading
import time
from collections import deque
from contextlib import contextmanager
from typing import Any, Iterator

PROBE_MAX_CONCURRENT = 2
PROBE_DEDUP_TTL_S = 5.0
PROBE_RATE_LIMIT = 60
PROBE_RATE_WINDOW_S = 60.0


class ProbeBusyError(Exception):
    """Raised when the probe concurrency cap is already full."""


class ProbeGuard:
    """Thread-safe guard shared by the probe endpoints."""

    def __init__(self) -> None:
        self._semaphore = threading.Semaphore(PROBE_MAX_CONCURRENT)
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, Any]] = {}
        self._rates: dict[str, deque[float]] = {}

    @contextmanager
    def run_probe(self) -> Iterator[None]:
        """Hold one of the concurrent probe slots (non-blocking).

        Raises :class:`ProbeBusyError` immediately when both slots
        are busy — callers turn it into a 429.
        """
        if not self._semaphore.acquire(blocking=False):
            raise ProbeBusyError(
                "too many concurrent probes "
                f"(max {PROBE_MAX_CONCURRENT}); try again shortly"
            )
        try:
            yield
        finally:
            self._semaphore.release()

    def get_cached(self, key: str) -> Any | None:
        """A fresh (≤ TTL) cached result for ``key``, else None."""
        now = time.monotonic()
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            stored_at, result = entry
            if now - stored_at > PROBE_DEDUP_TTL_S:
                del self._cache[key]
                return None
            return copy.deepcopy(result)

    def put_cached(self, key: str, result: Any) -> None:
        with self._lock:
            self._cache[key] = (time.monotonic(), copy.deepcopy(result))

    def check_rate(self, client_id: str) -> bool:
        """True when ``client_id`` is still inside its rate budget."""
        now = time.monotonic()
        cutoff = now - PROBE_RATE_WINDOW_S
        with self._lock:
            window = self._rates.setdefault(client_id, deque())
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= PROBE_RATE_LIMIT:
                return False
            window.append(now)
            return True

    def reset(self) -> None:
        """Clear cache + rate windows (tests; also frees the slots
        if a probe leaked one — it cannot: the context manager
        always releases)."""
        with self._lock:
            self._cache.clear()
            self._rates.clear()


probe_guard = ProbeGuard()


def reset_probe_guard() -> None:
    """Test helper: clear the shared guard's cache and rate state."""
    probe_guard.reset()
