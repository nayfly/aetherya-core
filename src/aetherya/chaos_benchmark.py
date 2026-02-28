from __future__ import annotations

import argparse
import json
import math
import os
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from random import Random

from aetherya.audit import AuditLogger
from aetherya.audit_verify import verify_audit_file

_HEX_BYTES = b"0123456789abcdef"


@dataclass(frozen=True)
class ChaosRunResult:
    run_id: int
    events: int
    mutations: int
    latency_ms: float
    detected: bool
    detection_mode: str


@dataclass(frozen=True)
class ChaosBenchmarkResult:
    passed: bool
    runs: int
    events: int
    seed: int
    detection_rate: float
    latency_ms_p50: float
    latency_ms_p95: float
    latency_ms_p99: float
    latency_ms_max: float
    thresholds: dict[str, float]
    results: list[ChaosRunResult]


def _resolve_attestation_key(explicit_key: str | None) -> str:
    raw = explicit_key if explicit_key is not None else os.getenv("AETHERYA_ATTESTATION_KEY", "")
    cleaned = raw.strip() if isinstance(raw, str) else ""
    return cleaned if cleaned else "chaos-benchmark-key"


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if pct <= 0.0:
        return min(values)
    if pct >= 100.0:
        return max(values)
    sorted_values = sorted(values)
    rank = math.ceil((pct / 100.0) * len(sorted_values))
    rank_index = max(0, min(len(sorted_values) - 1, rank - 1))
    return sorted_values[rank_index]


def _round4(value: float) -> float:
    return round(float(value), 4)


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


def _writer(path: Path, *, total: int, attestation_key: str, done: threading.Event) -> None:
    logger = AuditLogger(str(path), attestation_key=attestation_key)
    for idx in range(total):
        logger.log(
            actor="chaos-benchmark-writer",
            action=f"event-{idx}",
            decision={"allowed": True, "risk_score": idx % 7, "state": "allow"},
            context={"mode": "consultive", "trace_id": f"chaos-{idx}"},
        )
        time.sleep(0.0004)
    done.set()


def _mutator(path: Path, done: threading.Event, mutation_counter: list[int], rng_seed: int) -> None:
    rng = Random(rng_seed)
    while not done.is_set():
        if _mutate_chain_hash_byte(path, rng):
            mutation_counter[0] += 1
        time.sleep(0.0002)


def _run_single_chaos(
    *,
    path: Path,
    events: int,
    attestation_key: str,
    run_seed: int,
) -> tuple[int, float, bool, str]:
    if path.exists():
        path.unlink()

    done = threading.Event()
    mutation_counter = [0]

    writer_thread = threading.Thread(
        target=_writer,
        args=(path,),
        kwargs={"total": events, "attestation_key": attestation_key, "done": done},
    )
    mutator_thread = threading.Thread(
        target=_mutator,
        args=(path, done, mutation_counter, run_seed),
    )
    writer_thread.start()
    mutator_thread.start()
    writer_thread.join()
    done.set()
    mutator_thread.join(timeout=1.0)

    if mutation_counter[0] == 0:
        rng = Random(run_seed)
        for _ in range(8):
            if _mutate_chain_hash_byte(path, rng):
                mutation_counter[0] = 1
                break

    start_ns = time.perf_counter_ns()
    detected = False
    detection_mode = "none"
    try:
        records = verify_audit_file(
            path,
            require_hmac=True,
            require_chain=True,
            attestation_key=attestation_key,
        )
        detected = any(not record.verification.valid for record in records)
        if detected:
            detection_mode = "chain_validation"
    except ValueError:
        detected = True
        detection_mode = "json_corruption"
    latency_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
    return mutation_counter[0], latency_ms, detected, detection_mode


def run_chaos_benchmark(
    *,
    runs: int = 25,
    events: int = 48,
    seed: int = 1337,
    p95_max_ms: float = 10.0,
    p99_max_ms: float = 15.0,
    attestation_key: str | None = None,
    workdir: str | Path = "audit/chaos",
) -> ChaosBenchmarkResult:
    if runs <= 0:
        raise ValueError("runs must be > 0")
    if events <= 0:
        raise ValueError("events must be > 0")
    if p95_max_ms <= 0.0:
        raise ValueError("p95_max_ms must be > 0")
    if p99_max_ms <= 0.0:
        raise ValueError("p99_max_ms must be > 0")

    resolved_key = _resolve_attestation_key(attestation_key)
    resolved_workdir = Path(workdir)
    resolved_workdir.mkdir(parents=True, exist_ok=True)

    results: list[ChaosRunResult] = []
    latencies: list[float] = []
    detected_count = 0

    for run_id in range(runs):
        run_path = resolved_workdir / f"chaos_run_{run_id}.jsonl"
        mutations, latency_ms, detected, detection_mode = _run_single_chaos(
            path=run_path,
            events=events,
            attestation_key=resolved_key,
            run_seed=seed + run_id,
        )
        if detected:
            detected_count += 1
        latencies.append(latency_ms)
        results.append(
            ChaosRunResult(
                run_id=run_id,
                events=events,
                mutations=mutations,
                latency_ms=_round4(latency_ms),
                detected=detected,
                detection_mode=detection_mode,
            )
        )

    p50 = _percentile(latencies, 50.0)
    p95 = _percentile(latencies, 95.0)
    p99 = _percentile(latencies, 99.0)
    max_latency = max(latencies) if latencies else 0.0
    detection_rate = detected_count / runs

    passed = detection_rate == 1.0 and p95 <= p95_max_ms and p99 <= p99_max_ms
    return ChaosBenchmarkResult(
        passed=passed,
        runs=runs,
        events=events,
        seed=seed,
        detection_rate=_round4(detection_rate),
        latency_ms_p50=_round4(p50),
        latency_ms_p95=_round4(p95),
        latency_ms_p99=_round4(p99),
        latency_ms_max=_round4(max_latency),
        thresholds={
            "p95_max_ms": _round4(p95_max_ms),
            "p99_max_ms": _round4(p99_max_ms),
            "detection_rate_required": 1.0,
        },
        results=results,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run AETHERYA chaos benchmark with latency SLOs.")
    parser.add_argument("--runs", type=int, default=25, help="Benchmark iterations.")
    parser.add_argument("--events", type=int, default=48, help="Events per run.")
    parser.add_argument("--seed", type=int, default=1337, help="Deterministic seed.")
    parser.add_argument(
        "--p95-max-ms",
        type=float,
        default=10.0,
        help="Maximum allowed p95 detection latency in milliseconds.",
    )
    parser.add_argument(
        "--p99-max-ms",
        type=float,
        default=15.0,
        help="Maximum allowed p99 detection latency in milliseconds.",
    )
    parser.add_argument(
        "--attestation-key",
        default=None,
        help="Optional HMAC key (fallback env AETHERYA_ATTESTATION_KEY).",
    )
    parser.add_argument(
        "--workdir",
        default="audit/chaos",
        help="Directory for generated chaos logs.",
    )
    parser.add_argument(
        "--output",
        default="audit/chaos/chaos_benchmark_metrics.json",
        help="JSON output path.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON payload to stdout.")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        result = run_chaos_benchmark(
            runs=args.runs,
            events=args.events,
            seed=args.seed,
            p95_max_ms=args.p95_max_ms,
            p99_max_ms=args.p99_max_ms,
            attestation_key=args.attestation_key,
            workdir=args.workdir,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    payload = asdict(result)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(
            "chaos_benchmark "
            f"passed={result.passed} "
            f"detection_rate={result.detection_rate:.4f} "
            f"p95_ms={result.latency_ms_p95:.4f} "
            f"p99_ms={result.latency_ms_p99:.4f}"
        )

    return 0 if result.passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
