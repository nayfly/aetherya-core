from __future__ import annotations

import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aetherya.audit import AuditEvent

# Process-level registry. `AuditLogger` instances are commonly built per request
# (see `api.py`), so mirror health cannot be read off a logger — it has to live
# with the sink. `/health` reads this registry.
_REGISTRY: list[DurableAuditSink] = []
_REGISTRY_LOCK = threading.Lock()


def register_sink(sink: DurableAuditSink) -> DurableAuditSink:
    with _REGISTRY_LOCK:
        _REGISTRY.append(sink)
    return sink


def registered_sinks() -> list[DurableAuditSink]:
    with _REGISTRY_LOCK:
        return list(_REGISTRY)


def clear_registry() -> None:
    """Reset the registry (tests and process re-initialisation)."""
    with _REGISTRY_LOCK:
        _REGISTRY.clear()


def mirror_health() -> dict[str, Any]:
    """
    Aggregate mirror state for /health.

    A mirror that fails silently is worse than no mirror: shipping is
    best-effort by design (an archive outage must not stop decisions), so the
    only thing standing between "durable audit" and "local file that looks
    durable" is this being alerted on.
    """
    sinks = registered_sinks()
    if not sinks:
        return {"audit_mirror_configured": False}

    stats = [sink.stats() for sink in sinks]
    return {
        "audit_mirror_configured": True,
        "audit_mirror_ok": all(s["healthy"] for s in stats),
        "audit_mirror_errors_total": sum(int(s["errors"]) for s in stats),
        "audit_mirror_dropped_total": sum(int(s["dropped"]) for s in stats),
        "audit_mirror_pending_total": sum(int(s["pending"]) for s in stats),
        "audit_last_mirror_success": max(
            (s["last_success_ts"] for s in stats if s["last_success_ts"] is not None),
            default=None,
        ),
        "audit_mirrors": stats,
    }


@dataclass
class _SinkStats:
    sent: int = 0
    errors: int = 0
    dropped: int = 0
    last_success_ts: float | None = None
    last_error: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


class DurableAuditSink:
    """Base class providing the shared counters `/health` reports on."""

    def __init__(self, *, name: str) -> None:
        self.name = name
        self._stats = _SinkStats()

    def pending(self) -> int:
        return 0

    def _healthy_locked(self) -> bool:
        if self._stats.errors == 0:
            return True
        return self._stats.last_success_ts is not None and self._stats.dropped == 0

    def healthy(self) -> bool:
        """A sink is unhealthy once it has failed and not since succeeded."""
        with self._stats.lock:
            return self._healthy_locked()

    def stats(self) -> dict[str, Any]:
        # LOCK ORDER: queue lock before stats lock, never the reverse, and no
        # nested acquisition of either (threading.Lock is not reentrant). Both
        # rules are load-bearing: `pending()` takes the queue lock and
        # `_healthy_locked` assumes the stats lock is already held.
        pending = self.pending()
        with self._stats.lock:
            return {
                "name": self.name,
                "sent": self._stats.sent,
                "errors": self._stats.errors,
                "dropped": self._stats.dropped,
                "last_success_ts": self._stats.last_success_ts,
                "last_error": self._stats.last_error,
                "pending": pending,
                "healthy": self._healthy_locked(),
            }

    def _record_success(self, count: int) -> None:
        with self._stats.lock:
            self._stats.sent += count
            self._stats.last_success_ts = time.time()

    def _record_error(self, exc: BaseException) -> None:
        with self._stats.lock:
            self._stats.errors += 1
            self._stats.last_error = f"{type(exc).__name__}: {exc}"

    def _record_drop(self, count: int) -> None:
        with self._stats.lock:
            self._stats.dropped += count

    def write(self, event: AuditEvent, line: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class HTTPAuditSink(DurableAuditSink):
    """
    Ships audit lines to an HTTP ingest endpoint (Loki, Vector, Splunk HEC, a
    custom collector, or an S3-fronting service).

    The mirror sends the **byte-identical line** the primary wrote, so chain
    verification produces the same result on either copy — no re-serialization
    that could reorder keys and change a hash.

    Delivery shape:
    - Events queue in memory and a background thread flushes them in batches.
      A decision never waits on the network.
    - The queue is bounded. When full, the oldest pending events are dropped and
      counted, because unbounded growth under a sustained outage would take the
      process down — a worse failure than a gap in the archive.
    - Failed batches are retried on the next flush until `max_retries`, then
      dropped and counted.

    WORM/retention is a property of the destination, not of this sink: point it
    at object-lock storage or an append-only log service if you need those
    guarantees.
    """

    def __init__(
        self,
        url: str,
        *,
        name: str = "http",
        headers: dict[str, str] | None = None,
        batch_size: int = 50,
        flush_interval_sec: float = 2.0,
        max_queue: int = 10_000,
        timeout_sec: float = 5.0,
        max_retries: int = 3,
        start: bool = True,
    ) -> None:
        super().__init__(name=name)
        self.url = url
        self.headers = {"Content-Type": "application/x-ndjson", **(headers or {})}
        self.batch_size = max(1, int(batch_size))
        self.flush_interval_sec = float(flush_interval_sec)
        self.max_queue = max(1, int(max_queue))
        self.timeout_sec = float(timeout_sec)
        self.max_retries = max(0, int(max_retries))

        self._queue: list[str] = []
        self._queue_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        if start:
            self.start()

    # -- lifecycle ------------------------------------------------------------

    def start(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        self._stop.clear()
        self._worker = threading.Thread(
            target=self._run, name=f"aetherya-audit-sink-{self.name}", daemon=True
        )
        self._worker.start()

    def close(self, timeout: float = 5.0) -> None:
        """Stop the worker and drain everything still queued."""
        self._stop.set()
        self._wake.set()
        worker = self._worker
        if worker is not None and worker.is_alive():
            worker.join(timeout=timeout)
        self.drain()

    def drain(self, max_batches: int = 1000) -> int:
        """
        Flush batches until the queue is empty or no progress is made.

        `close()` must not leave events behind: a single `flush_once()` sends at
        most one batch, so shutting down with a backlog would silently lose the
        tail of the audit trail.
        """
        delivered = 0
        for _ in range(max_batches):
            if self.pending() == 0:
                break
            sent = self.flush_once()
            if sent == 0:
                break  # persistent failure — stop rather than spin
            delivered += sent
        return delivered

    def pending(self) -> int:
        with self._queue_lock:
            return len(self._queue)

    # -- producer side --------------------------------------------------------

    def write(self, event: AuditEvent, line: str) -> None:
        with self._queue_lock:
            self._queue.append(line)
            overflow = len(self._queue) - self.max_queue
            if overflow > 0:
                # Drop oldest: the newest events are the ones an operator is
                # most likely to be looking for during an incident.
                del self._queue[:overflow]
            should_wake = len(self._queue) >= self.batch_size

        # Counters are updated outside the queue lock to keep the lock order
        # (queue -> stats) one-directional.
        if overflow > 0:
            self._record_drop(overflow)
        if should_wake:
            self._wake.set()

    # -- consumer side --------------------------------------------------------

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=self.flush_interval_sec)
            self._wake.clear()
            self.flush_once()

    def _take_batch(self) -> list[str]:
        with self._queue_lock:
            batch = self._queue[: self.batch_size]
            del self._queue[: len(batch)]
            return batch

    def flush_once(self) -> int:
        """Send at most one batch. Returns how many lines were delivered."""
        batch = self._take_batch()
        if not batch:
            return 0

        for attempt in range(self.max_retries + 1):
            try:
                self._post(batch)
                self._record_success(len(batch))
                return len(batch)
            except Exception as exc:
                self._record_error(exc)
                if attempt >= self.max_retries:
                    self._record_drop(len(batch))
                    return 0
                time.sleep(min(0.5 * (2**attempt), 2.0))
        return 0  # pragma: no cover - loop always returns

    def _post(self, batch: list[str]) -> None:
        payload = ("\n".join(batch) + "\n").encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - operator-configured URL
            self.url, data=payload, headers=self.headers, method="POST"
        )
        # urlopen already raises HTTPError for 4xx/5xx, which flush_once counts
        # as a failed batch — no additional status check is needed here.
        with urllib.request.urlopen(request, timeout=self.timeout_sec):  # noqa: S310
            pass


class FileAuditSink(DurableAuditSink):
    """
    Mirrors to a second file path — useful when the second path is a mounted
    volume that outlives the container, or a directory an archival agent tails.

    Simpler and synchronous: no queue, no worker. If the write fails the error
    is raised to `AuditLogger`, which counts it without breaking the decision.
    """

    def __init__(self, path: str, *, name: str = "file") -> None:
        super().__init__(name=name)
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: AuditEvent, line: str) -> None:
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except Exception as exc:
            self._record_error(exc)
            raise
        self._record_success(1)


def build_http_sink_from_env(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> HTTPAuditSink:
    """Construct an HTTP sink and register it so /health can report on it."""
    sink = HTTPAuditSink(url, headers=headers, **kwargs)
    register_sink(sink)
    return sink


__all__ = [
    "DurableAuditSink",
    "FileAuditSink",
    "HTTPAuditSink",
    "build_http_sink_from_env",
    "clear_registry",
    "mirror_health",
    "register_sink",
    "registered_sinks",
]
