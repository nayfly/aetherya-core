from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from aetherya.audit import AuditEvent, AuditLogger
from aetherya.audit_sink import (
    DurableAuditSink,
    FileAuditSink,
    HTTPAuditSink,
    build_http_sink_from_env,
    clear_registry,
    mirror_health,
    register_sink,
    registered_sinks,
)


@pytest.fixture(autouse=True)
def _clean_registry() -> Any:
    clear_registry()
    yield
    clear_registry()


class _Collector(BaseHTTPRequestHandler):
    lines: list[str] = []
    status = 204
    fail_times = 0

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        if type(self).fail_times > 0:
            type(self).fail_times -= 1
            self.send_response(500)
            self.end_headers()
            return
        type(self).lines.extend(body.strip().splitlines())
        self.send_response(type(self).status)
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def collector() -> Any:
    _Collector.lines = []
    _Collector.status = 204
    _Collector.fail_times = 0
    server = HTTPServer(("127.0.0.1", 0), _Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


def _url(server: Any, path: str = "/ingest") -> str:
    return f"http://127.0.0.1:{server.server_port}{path}"


def _log(logger: AuditLogger, action: str = "do thing") -> None:
    logger.log(actor="robert", action=action, decision={"allowed": True}, context={})


# ---------------------------------------------------------------------------
# HTTP sink delivery
# ---------------------------------------------------------------------------


def test_mirrored_lines_are_byte_identical_to_the_primary(collector: Any, tmp_path: Path) -> None:
    """
    Chain verification must produce the same result on either copy, so the sink
    forwards the exact serialized line — never a re-serialization that could
    reorder keys and change a hash.
    """
    sink = HTTPAuditSink(_url(collector), batch_size=3, flush_interval_sec=0.05)
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    for i in range(7):
        _log(logger, f"action-{i}")
    sink.close()

    local = (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(local) == 7
    assert _Collector.lines == local


def test_close_drains_a_partial_batch(collector: Any, tmp_path: Path) -> None:
    """Shutting down with a backlog must not lose the tail of the audit trail."""
    sink = HTTPAuditSink(_url(collector), batch_size=50, flush_interval_sec=30.0)
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    for _ in range(4):
        _log(logger)

    assert sink.pending() == 4
    sink.close()
    assert sink.pending() == 0
    assert len(_Collector.lines) == 4


def test_decisions_do_not_wait_on_the_network(collector: Any, tmp_path: Path) -> None:
    sink = HTTPAuditSink(_url(collector), batch_size=1000, flush_interval_sec=30.0)
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    _log(logger)

    # Queued, not yet delivered — the write returned without a round trip.
    assert sink.pending() == 1
    assert _Collector.lines == []
    sink.close()


def test_a_failing_batch_is_retried_then_delivered(collector: Any, tmp_path: Path) -> None:
    _Collector.fail_times = 2
    sink = HTTPAuditSink(
        _url(collector), batch_size=1, flush_interval_sec=30.0, max_retries=3, start=False
    )
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    _log(logger)

    assert sink.flush_once() == 1
    assert len(_Collector.lines) == 1
    assert sink.stats()["errors"] == 2


def test_exhausted_retries_drop_and_count(collector: Any, tmp_path: Path) -> None:
    _Collector.fail_times = 99
    sink = HTTPAuditSink(
        _url(collector), batch_size=1, flush_interval_sec=30.0, max_retries=1, start=False
    )
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    _log(logger)

    assert sink.flush_once() == 0
    stats = sink.stats()
    assert stats["dropped"] == 1
    assert stats["healthy"] is False


def test_a_rejecting_endpoint_is_treated_as_a_failure(collector: Any, tmp_path: Path) -> None:
    _Collector.status = 418
    sink = HTTPAuditSink(
        _url(collector), batch_size=1, flush_interval_sec=30.0, max_retries=0, start=False
    )
    AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink]).log(
        actor="r", action="x", decision={"allowed": True}, context={}
    )
    assert sink.flush_once() == 0
    assert sink.stats()["errors"] >= 1


def test_the_decision_still_lands_locally_when_the_archive_is_down(tmp_path: Path) -> None:
    """An archive outage must not stop decisions or lose the local record."""
    sink = HTTPAuditSink("http://127.0.0.1:1/nope", batch_size=1, max_retries=0, start=False)
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    _log(logger)
    sink.flush_once()

    assert len((tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()) == 1
    assert sink.stats()["healthy"] is False


# ---------------------------------------------------------------------------
# Bounded queue
# ---------------------------------------------------------------------------


def test_queue_is_bounded_and_drops_oldest(tmp_path: Path) -> None:
    """
    Unbounded growth under a sustained outage would take the process down —
    a worse failure than a gap in the archive.
    """
    sink = HTTPAuditSink("http://127.0.0.1:1/nope", max_queue=5, batch_size=100, start=False)
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    for i in range(20):
        _log(logger, f"action-{i}")

    assert sink.pending() == 5
    assert sink.stats()["dropped"] == 15
    # Oldest dropped, newest retained: those are what an incident needs.
    assert "action-19" in sink._queue[-1]  # noqa: SLF001


def test_flush_on_an_empty_queue_is_a_noop() -> None:
    sink = HTTPAuditSink("http://127.0.0.1:1/nope", start=False)
    assert sink.flush_once() == 0
    assert sink.drain() == 0


def test_drain_stops_when_no_progress_is_made(tmp_path: Path) -> None:
    sink = HTTPAuditSink(
        "http://127.0.0.1:1/nope", batch_size=1, max_queue=10, max_retries=0, start=False
    )
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    for _ in range(5):
        _log(logger)

    assert sink.drain() == 0  # returns rather than spinning
    assert sink.pending() < 5


# ---------------------------------------------------------------------------
# Locking
# ---------------------------------------------------------------------------


def test_stats_does_not_deadlock(tmp_path: Path) -> None:
    """
    Regression: `stats()` held the stats lock and called `healthy()`, which took
    it again — threading.Lock is not reentrant — and `pending()` took the queue
    lock in the opposite order to `write()`.
    """
    sink = HTTPAuditSink("http://127.0.0.1:1/nope", start=False)
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])

    done = threading.Event()

    def reader() -> None:
        for _ in range(200):
            sink.stats()
            sink.healthy()
        done.set()

    thread = threading.Thread(target=reader)
    thread.start()
    for _ in range(200):
        _log(logger)
    thread.join(timeout=10)

    assert done.is_set(), "stats()/write() deadlocked"


def test_concurrent_writers_do_not_lose_events(tmp_path: Path) -> None:
    sink = HTTPAuditSink("http://127.0.0.1:1/nope", max_queue=10_000, start=False)
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])

    def writer() -> None:
        for _ in range(50):
            _log(logger)

    threads = [threading.Thread(target=writer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert sink.pending() == 400


# ---------------------------------------------------------------------------
# File sink
# ---------------------------------------------------------------------------


def test_file_sink_mirrors_byte_identically(tmp_path: Path) -> None:
    mirror = tmp_path / "mirror" / "audit.jsonl"
    sink = FileAuditSink(str(mirror))
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    for _ in range(3):
        _log(logger)

    assert mirror.read_text(encoding="utf-8") == (tmp_path / "a.jsonl").read_text(encoding="utf-8")
    assert sink.stats()["sent"] == 3


def test_file_sink_failure_is_counted_and_contained(tmp_path: Path) -> None:
    sink = FileAuditSink(str(tmp_path / "mirror.jsonl"))
    sink.path = tmp_path / "missing-dir" / "mirror.jsonl"
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])

    _log(logger)  # must not raise

    assert sink.stats()["errors"] == 1
    assert logger.mirror_errors == 1
    assert len((tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()) == 1


# ---------------------------------------------------------------------------
# Registry and health
# ---------------------------------------------------------------------------


def test_health_reports_no_mirror_when_none_registered() -> None:
    assert mirror_health() == {"audit_mirror_configured": False}


def test_health_aggregates_registered_sinks(collector: Any, tmp_path: Path) -> None:
    good = register_sink(FileAuditSink(str(tmp_path / "mirror.jsonl"), name="file"))
    bad = register_sink(
        HTTPAuditSink("http://127.0.0.1:1/nope", batch_size=1, max_retries=0, start=False)
    )
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[good, bad])
    _log(logger)
    bad.flush_once()

    health = mirror_health()
    assert health["audit_mirror_configured"] is True
    assert health["audit_mirror_ok"] is False
    assert health["audit_mirror_errors_total"] >= 1
    assert health["audit_last_mirror_success"] is not None
    assert {m["name"] for m in health["audit_mirrors"]} == {"file", "http"}


def test_health_reports_ok_when_every_sink_is_healthy(tmp_path: Path) -> None:
    register_sink(FileAuditSink(str(tmp_path / "mirror.jsonl")))
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=registered_sinks())
    _log(logger)

    health = mirror_health()
    assert health["audit_mirror_ok"] is True
    assert health["audit_mirror_errors_total"] == 0


def test_health_surfaces_the_pending_backlog(tmp_path: Path) -> None:
    sink = register_sink(HTTPAuditSink("http://127.0.0.1:1/nope", batch_size=1000, start=False))
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    for _ in range(5):
        _log(logger)

    assert mirror_health()["audit_mirror_pending_total"] == 5


def test_api_health_includes_mirror_state(tmp_path: Path) -> None:
    from aetherya.api import AetheryaAPI, APISettings

    register_sink(FileAuditSink(str(tmp_path / "mirror.jsonl")))
    _, body = AetheryaAPI(APISettings(audit_path=tmp_path / "a.jsonl")).health()

    assert body["audit_mirror_configured"] is True
    assert body["audit_mirror_ok"] is True


def test_build_http_sink_registers_it() -> None:
    sink = build_http_sink_from_env("http://127.0.0.1:1/nope", start=False)
    assert sink in registered_sinks()
    assert mirror_health()["audit_mirror_configured"] is True


def test_clear_registry_empties_it(tmp_path: Path) -> None:
    register_sink(FileAuditSink(str(tmp_path / "m.jsonl")))
    assert registered_sinks()
    clear_registry()
    assert registered_sinks() == []


def test_base_sink_write_is_abstract() -> None:
    with pytest.raises(NotImplementedError):
        DurableAuditSink(name="base").write(
            AuditEvent(
                event_id="e",
                decision_id="d",
                context_hash="c",
                prev_chain_hash=None,
                chain_hash="h",
                policy_fingerprint=None,
                attestation_alg="sha256",
                attestation="a",
                ts="t",
                actor="r",
                action="x",
                decision={},
                context={},
            ),
            "line",
        )


def test_start_is_idempotent() -> None:
    sink = HTTPAuditSink("http://127.0.0.1:1/nope", flush_interval_sec=30.0)
    worker = sink._worker  # noqa: SLF001
    sink.start()
    assert sink._worker is worker  # noqa: SLF001
    sink.close()


def test_close_without_a_started_worker_is_safe() -> None:
    sink = HTTPAuditSink("http://127.0.0.1:1/nope", start=False)
    sink.close()  # must not raise


def test_headers_are_merged_over_the_default_content_type() -> None:
    sink = HTTPAuditSink("http://127.0.0.1:1/x", headers={"Authorization": "Bearer t"}, start=False)
    assert sink.headers["Authorization"] == "Bearer t"
    assert sink.headers["Content-Type"] == "application/x-ndjson"


def test_degenerate_settings_are_clamped() -> None:
    sink = HTTPAuditSink(
        "http://127.0.0.1:1/x", batch_size=0, max_queue=0, max_retries=-5, start=False
    )
    assert sink.batch_size == 1
    assert sink.max_queue == 1
    assert sink.max_retries == 0


def test_drain_respects_max_batches(collector: Any, tmp_path: Path) -> None:
    """A bounded drain must stop at the limit rather than loop indefinitely."""
    sink = HTTPAuditSink(_url(collector), batch_size=1, flush_interval_sec=30.0, start=False)
    logger = AuditLogger(str(tmp_path / "a.jsonl"), mirrors=[sink])
    for _ in range(5):
        _log(logger)

    assert sink.drain(max_batches=2) == 2
    assert sink.pending() == 3
