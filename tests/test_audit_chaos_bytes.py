from __future__ import annotations

import threading
import time
from pathlib import Path
from random import Random

from aetherya.audit import AuditLogger
from aetherya.audit_verify import verify_audit_file

_HEX_BYTES = b"0123456789abcdef"


def _mutate_chain_hash_byte(path: Path, rng: Random) -> bool:
    if not path.exists():
        return False

    payload = bytearray(path.read_bytes())
    markers = (
        b'"chain_hash":"sha256:',
        b'"chain_hash": "sha256:',
        b'"prev_chain_hash":"sha256:',
        b'"prev_chain_hash": "sha256:',
    )

    positions: list[int] = []
    for marker in markers:
        offset = 0
        while True:
            idx = payload.find(marker, offset)
            if idx < 0:
                break
            start = idx + len(marker)
            end = min(len(payload), start + 64)
            for pos in range(start, end):
                if payload[pos] in _HEX_BYTES:
                    positions.append(pos)
            offset = idx + 1

    if not positions:
        return False

    pos = positions[rng.randrange(len(positions))]
    old = payload[pos]
    replacement_pool = [b for b in _HEX_BYTES if b != old]
    payload[pos] = replacement_pool[rng.randrange(len(replacement_pool))]
    path.write_bytes(payload)
    return True


def _writer(path: Path, *, total: int, done: threading.Event) -> None:
    logger = AuditLogger(path, attestation_key="chaos-key")
    for idx in range(total):
        logger.log(
            actor="chaos-writer",
            action=f"event-{idx}",
            decision={"allowed": True, "risk_score": idx % 7, "state": "allow"},
            context={"mode": "consultive", "trace_id": f"chaos-{idx}"},
        )
        time.sleep(0.0004)
    done.set()


def _mutator(path: Path, done: threading.Event, mutation_counter: list[int]) -> None:
    rng = Random(1337)
    while not done.is_set():
        if _mutate_chain_hash_byte(path, rng):
            mutation_counter[0] += 1
        time.sleep(0.0002)


def test_chaos_byte_mutator_detects_chain_break_under_10ms(tmp_path: Path) -> None:
    path = tmp_path / "decisions.jsonl"
    done = threading.Event()
    mutation_counter = [0]

    writer_thread = threading.Thread(
        target=_writer, args=(path,), kwargs={"total": 48, "done": done}
    )
    mutator_thread = threading.Thread(target=_mutator, args=(path, done, mutation_counter))

    writer_thread.start()
    mutator_thread.start()
    writer_thread.join()
    done.set()
    mutator_thread.join(timeout=1.0)

    if mutation_counter[0] == 0:
        rng = Random(1337)
        for _ in range(8):
            if _mutate_chain_hash_byte(path, rng):
                mutation_counter[0] = 1
                break

    start_ns = time.perf_counter_ns()
    records = []
    detected = False
    try:
        records = verify_audit_file(
            path,
            require_hmac=True,
            require_chain=True,
            attestation_key="chaos-key",
        )
        invalid = [record for record in records if not record.verification.valid]
        detected = bool(invalid)
    except ValueError:
        # Concurrent byte corruption may break JSON framing before chain validation.
        detected = True
    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

    invalid = [record for record in records if not record.verification.valid]
    all_errors = [error for record in invalid for error in record.verification.errors]

    assert mutation_counter[0] > 0
    assert detected is True
    if invalid:
        assert any(error == "chain_hash mismatch" for error in all_errors)
    assert elapsed_ms < 10.0
