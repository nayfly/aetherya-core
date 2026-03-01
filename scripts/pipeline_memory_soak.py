#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gc
import json
import time
from pathlib import Path

from aetherya.pipeline_benchmark import run_pipeline_benchmark


def _current_rss_kb() -> int:
    status_path = Path("/proc/self/status")
    if not status_path.exists():
        return 0
    for line in status_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run pipeline benchmark in a long loop and monitor RSS growth."
    )
    parser.add_argument("--duration-sec", type=int, default=600, help="Soak duration in seconds.")
    parser.add_argument(
        "--sleep-ms", type=int, default=0, help="Optional pause between iterations (milliseconds)."
    )
    parser.add_argument("--runs", type=int, default=1, help="Benchmark runs per iteration.")
    parser.add_argument("--corpus-size", type=int, default=100, help="Inputs per benchmark run.")
    parser.add_argument("--seed", type=int, default=1337, help="Deterministic corpus seed.")
    parser.add_argument(
        "--max-rss-growth-mb",
        type=float,
        default=128.0,
        help="Fail if RSS growth exceeds this threshold.",
    )
    parser.add_argument(
        "--output",
        default="audit/pipeline/pipeline_memory_soak.json",
        help="JSON report output path.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON payload.")
    args = parser.parse_args(argv)

    if args.duration_sec <= 0:
        raise ValueError("duration_sec must be > 0")
    if args.runs <= 0:
        raise ValueError("runs must be > 0")
    if args.corpus_size <= 0:
        raise ValueError("corpus_size must be > 0")
    if args.max_rss_growth_mb <= 0.0:
        raise ValueError("max_rss_growth_mb must be > 0")

    start = time.monotonic()
    deadline = start + float(args.duration_sec)

    baseline_rss_kb = _current_rss_kb()
    max_rss_kb = baseline_rss_kb
    iterations = 0
    total_evaluations = 0
    sampled_rss_kb: list[int] = []

    while time.monotonic() < deadline:
        result = run_pipeline_benchmark(
            runs=args.runs,
            corpus_size=args.corpus_size,
            seed=args.seed + iterations,
            p95_max_ms=10_000.0,
            p99_max_ms=10_000.0,
            actor="robert",
            policy_path="config/policy.yaml",
        )
        total_evaluations += int(result.evaluations)
        iterations += 1
        current_rss_kb = _current_rss_kb()
        sampled_rss_kb.append(current_rss_kb)
        if current_rss_kb > max_rss_kb:
            max_rss_kb = current_rss_kb

        if iterations % 5 == 0:
            gc.collect()
        if args.sleep_ms > 0:
            time.sleep(args.sleep_ms / 1000.0)

    elapsed_sec = round(time.monotonic() - start, 4)
    rss_growth_kb = max(0, max_rss_kb - baseline_rss_kb)
    rss_growth_mb = round(rss_growth_kb / 1024.0, 4)
    passed = rss_growth_mb <= float(args.max_rss_growth_mb)

    payload = {
        "passed": passed,
        "duration_sec": elapsed_sec,
        "iterations": iterations,
        "total_evaluations": total_evaluations,
        "baseline_rss_kb": baseline_rss_kb,
        "max_rss_kb": max_rss_kb,
        "rss_growth_kb": rss_growth_kb,
        "rss_growth_mb": rss_growth_mb,
        "max_rss_growth_mb": float(args.max_rss_growth_mb),
        "sample_count": len(sampled_rss_kb),
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(
            "pipeline_memory_soak "
            f"passed={payload['passed']} "
            f"iterations={iterations} "
            f"growth_mb={rss_growth_mb:.4f}"
        )

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
