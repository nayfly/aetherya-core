from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import aetherya.pipeline_benchmark as pipeline_benchmark


def test_percentile_handles_edges() -> None:
    values = [1.0, 2.0, 3.0, 4.0]
    assert pipeline_benchmark._percentile(values, 0.0) == 1.0  # noqa: SLF001
    assert pipeline_benchmark._percentile(values, 100.0) == 4.0  # noqa: SLF001
    assert pipeline_benchmark._percentile(values, 50.0) == 2.0  # noqa: SLF001
    assert pipeline_benchmark._percentile([], 95.0) == 0.0  # noqa: SLF001


def test_build_input_corpus_validates_size() -> None:
    with pytest.raises(ValueError, match="corpus_size must be > 0"):
        pipeline_benchmark._build_input_corpus(0, 1337)  # noqa: SLF001


def test_build_input_corpus_is_deterministic_and_varied() -> None:
    corpus_a = pipeline_benchmark._build_input_corpus(12, 1337)  # noqa: SLF001
    corpus_b = pipeline_benchmark._build_input_corpus(12, 1337)  # noqa: SLF001
    assert corpus_a == corpus_b
    assert len(corpus_a) == 12
    assert len(set(corpus_a)) > 3


def test_run_pipeline_benchmark_passes_with_relaxed_thresholds() -> None:
    result = pipeline_benchmark.run_pipeline_benchmark(
        runs=1,
        corpus_size=20,
        seed=1337,
        p95_max_ms=100.0,
        p99_max_ms=120.0,
        policy_path="config/policy.yaml",
    )
    assert result.passed is True
    assert result.evaluations == 20
    assert len(result.samples) == 20


def test_run_pipeline_benchmark_fails_with_strict_thresholds() -> None:
    result = pipeline_benchmark.run_pipeline_benchmark(
        runs=1,
        corpus_size=20,
        seed=1337,
        p95_max_ms=0.0001,
        p99_max_ms=0.0001,
        policy_path="config/policy.yaml",
    )
    assert result.passed is False


def test_run_pipeline_benchmark_fails_when_evaluation_count_mismatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pipeline_benchmark, "_build_input_corpus", lambda corpus_size, seed: [])
    result = pipeline_benchmark.run_pipeline_benchmark(
        runs=1,
        corpus_size=10,
        seed=1337,
        p95_max_ms=100.0,
        p99_max_ms=120.0,
        policy_path="config/policy.yaml",
    )
    assert result.passed is False
    assert result.evaluations == 0


def test_run_pipeline_benchmark_semantic_warmup_not_counted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Warmup calls fire when use_semantic=True but are excluded from latency samples."""
    call_log: list[str] = []
    original_run = pipeline_benchmark.run_pipeline

    def counting_run(text: str, **kwargs: Any) -> Any:
        call_log.append(text)
        return original_run(text, **kwargs)

    # Patch constitution so no model download is triggered
    original_make = pipeline_benchmark._make_constitution  # noqa: SLF001

    def fast_constitution(use_semantic: bool = False) -> Any:
        return original_make(use_semantic=False)

    monkeypatch.setattr(pipeline_benchmark, "run_pipeline", counting_run)
    monkeypatch.setattr(pipeline_benchmark, "_make_constitution", fast_constitution)

    corpus_size = 5
    result = pipeline_benchmark.run_pipeline_benchmark(
        runs=1,
        corpus_size=corpus_size,
        seed=1337,
        p95_max_ms=100.0,
        p99_max_ms=120.0,
        use_semantic=True,
    )

    # _WARMUP_RUNS warmup calls + corpus_size measured calls
    assert len(call_log) == pipeline_benchmark._WARMUP_RUNS + corpus_size  # noqa: SLF001
    # Only the corpus_size calls end up in samples
    assert result.evaluations == corpus_size


def test_run_pipeline_benchmark_no_warmup_when_use_semantic_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No warmup calls are made when use_semantic=False."""
    call_log: list[str] = []
    original_run = pipeline_benchmark.run_pipeline

    def counting_run(text: str, **kwargs: Any) -> Any:
        call_log.append(text)
        return original_run(text, **kwargs)

    monkeypatch.setattr(pipeline_benchmark, "run_pipeline", counting_run)

    corpus_size = 5
    result = pipeline_benchmark.run_pipeline_benchmark(
        runs=1,
        corpus_size=corpus_size,
        seed=1337,
        p95_max_ms=100.0,
        p99_max_ms=120.0,
        use_semantic=False,
    )

    assert len(call_log) == corpus_size
    assert result.evaluations == corpus_size


def test_run_pipeline_benchmark_rejects_invalid_parameters() -> None:
    with pytest.raises(ValueError, match="runs must be > 0"):
        pipeline_benchmark.run_pipeline_benchmark(runs=0)
    with pytest.raises(ValueError, match="corpus_size must be > 0"):
        pipeline_benchmark.run_pipeline_benchmark(corpus_size=0)
    with pytest.raises(ValueError, match="p95_max_ms must be > 0"):
        pipeline_benchmark.run_pipeline_benchmark(p95_max_ms=0.0)
    with pytest.raises(ValueError, match="p99_max_ms must be > 0"):
        pipeline_benchmark.run_pipeline_benchmark(p99_max_ms=0.0)


def test_main_writes_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_path = tmp_path / "pipeline_metrics.json"
    code = pipeline_benchmark.main(
        [
            "--runs",
            "1",
            "--corpus-size",
            "20",
            "--p95-max-ms",
            "100",
            "--p99-max-ms",
            "120",
            "--output",
            str(output_path),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out.strip())
    assert code == 0
    assert output_path.exists()
    assert payload["passed"] is True


def test_main_prints_text_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_path = tmp_path / "pipeline_metrics.json"
    code = pipeline_benchmark.main(
        [
            "--runs",
            "1",
            "--corpus-size",
            "20",
            "--p95-max-ms",
            "100",
            "--p99-max-ms",
            "120",
            "--output",
            str(output_path),
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "pipeline_benchmark passed=True" in captured.out


def test_main_returns_error_on_invalid_args(capsys: pytest.CaptureFixture[str]) -> None:
    code = pipeline_benchmark.main(["--runs", "0"])
    captured = capsys.readouterr()
    assert code == 2
    assert "error: runs must be > 0" in captured.err
