from __future__ import annotations

import json
import threading
from pathlib import Path
from random import Random
from types import SimpleNamespace

import pytest

import aetherya.chaos_benchmark as chaos_benchmark


def test_percentile_handles_edges() -> None:
    values = [1.0, 2.0, 3.0, 4.0]
    assert chaos_benchmark._percentile(values, 0.0) == 1.0  # noqa: SLF001
    assert chaos_benchmark._percentile(values, 100.0) == 4.0  # noqa: SLF001
    assert chaos_benchmark._percentile(values, 50.0) == 2.0  # noqa: SLF001
    assert chaos_benchmark._percentile([], 95.0) == 0.0  # noqa: SLF001


def test_run_chaos_benchmark_passes_with_relaxed_thresholds(tmp_path: Path) -> None:
    result = chaos_benchmark.run_chaos_benchmark(
        runs=5,
        events=24,
        seed=1337,
        p95_max_ms=200.0,
        p99_max_ms=250.0,
        workdir=tmp_path / "chaos",
        attestation_key="chaos-key",
    )
    assert result.passed is True
    assert result.detection_rate == 1.0
    assert len(result.results) == 5


def test_run_chaos_benchmark_fails_with_strict_thresholds(tmp_path: Path) -> None:
    result = chaos_benchmark.run_chaos_benchmark(
        runs=3,
        events=12,
        seed=1337,
        p95_max_ms=0.0001,
        p99_max_ms=0.0001,
        workdir=tmp_path / "chaos",
        attestation_key="chaos-key",
    )
    assert result.passed is False
    assert result.detection_rate == 1.0


def test_run_chaos_benchmark_rejects_invalid_parameters(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="runs must be > 0"):
        chaos_benchmark.run_chaos_benchmark(
            runs=0,
            events=10,
            workdir=tmp_path / "w1",
        )
    with pytest.raises(ValueError, match="events must be > 0"):
        chaos_benchmark.run_chaos_benchmark(
            runs=1,
            events=0,
            workdir=tmp_path / "w2",
        )
    with pytest.raises(ValueError, match="p95_max_ms must be > 0"):
        chaos_benchmark.run_chaos_benchmark(
            runs=1,
            events=1,
            p95_max_ms=0.0,
            workdir=tmp_path / "w3",
        )
    with pytest.raises(ValueError, match="p99_max_ms must be > 0"):
        chaos_benchmark.run_chaos_benchmark(
            runs=1,
            events=1,
            p99_max_ms=0.0,
            workdir=tmp_path / "w4",
        )


def test_main_writes_output_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output_path = tmp_path / "chaos_metrics.json"
    code = chaos_benchmark.main(
        [
            "--runs",
            "3",
            "--events",
            "12",
            "--p95-max-ms",
            "200",
            "--p99-max-ms",
            "250",
            "--workdir",
            str(tmp_path / "chaos"),
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


def test_main_returns_error_on_invalid_args(capsys: pytest.CaptureFixture[str]) -> None:
    code = chaos_benchmark.main(["--runs", "0"])
    captured = capsys.readouterr()
    assert code == 2
    assert "error: runs must be > 0" in captured.err


def test_mutate_chain_hash_byte_ignores_non_hex_bytes(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text('{"chain_hash":"sha256:zzzzzzzz"}\n', encoding="utf-8")
    assert chaos_benchmark._mutate_chain_hash_byte(path, Random(1337)) is False  # noqa: SLF001


def test_mutate_chain_hash_byte_returns_false_for_missing_file(tmp_path: Path) -> None:
    missing_path = tmp_path / "does_not_exist.jsonl"
    result = chaos_benchmark._mutate_chain_hash_byte(missing_path, Random(1337))  # noqa: SLF001
    assert result is False


def test_mutator_does_not_increment_counter_when_mutation_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    done = threading.Event()
    mutation_counter = [0]

    def fake_mutate(path: Path, rng: Random) -> bool:  # noqa: ARG001
        done.set()
        return False

    monkeypatch.setattr(chaos_benchmark, "_mutate_chain_hash_byte", fake_mutate)
    chaos_benchmark._mutator(tmp_path / "audit.jsonl", done, mutation_counter, 1337)  # noqa: SLF001
    assert mutation_counter[0] == 0


def test_run_single_chaos_covers_unlink_fallback_and_no_detection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "chaos_run.jsonl"
    path.write_text("stale", encoding="utf-8")
    state: dict[str, bool] = {}

    def fake_writer(
        path: Path,
        *,
        total: int,
        attestation_key: str,
        done,  # noqa: ANN001, ARG001
    ) -> None:
        state["exists_before_write"] = path.exists()
        path.write_text("{}\n", encoding="utf-8")
        done.set()

    def fake_mutator(
        path: Path,
        done,
        mutation_counter: list[int],
        rng_seed: int,  # noqa: ANN001, ARG001
    ) -> None:
        return None

    attempts = {"count": 0}

    def fake_mutate(path: Path, rng: Random) -> bool:  # noqa: ARG001
        attempts["count"] += 1
        return True

    def fake_verify(*args, **kwargs):  # noqa: ANN002, ANN003, ARG001
        valid = SimpleNamespace(valid=True)
        return [SimpleNamespace(verification=valid)]

    monkeypatch.setattr(chaos_benchmark, "_writer", fake_writer)
    monkeypatch.setattr(chaos_benchmark, "_mutator", fake_mutator)
    monkeypatch.setattr(chaos_benchmark, "_mutate_chain_hash_byte", fake_mutate)
    monkeypatch.setattr(chaos_benchmark, "verify_audit_file", fake_verify)

    mutations, _, detected, mode = chaos_benchmark._run_single_chaos(  # noqa: SLF001
        path=path,
        events=2,
        attestation_key="chaos-key",
        run_seed=9,
    )
    assert state["exists_before_write"] is False
    assert attempts["count"] == 1
    assert mutations == 1
    assert detected is False
    assert mode == "none"


def test_run_single_chaos_fallback_exhausts_when_no_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "chaos_run_no_mutation.jsonl"

    def fake_writer(
        path: Path,
        *,
        total: int,  # noqa: ARG001
        attestation_key: str,  # noqa: ARG001
        done,  # noqa: ANN001
    ) -> None:
        path.write_text("{}\n", encoding="utf-8")
        done.set()

    def fake_mutator(
        path: Path,
        done,
        mutation_counter: list[int],
        rng_seed: int,  # noqa: ANN001, ARG001
    ) -> None:
        return None

    attempts = {"count": 0}

    def fake_mutate(path: Path, rng: Random) -> bool:  # noqa: ARG001
        attempts["count"] += 1
        return False

    def fake_verify(*args, **kwargs):  # noqa: ANN002, ANN003, ARG001
        invalid = SimpleNamespace(valid=False)
        return [SimpleNamespace(verification=invalid)]

    monkeypatch.setattr(chaos_benchmark, "_writer", fake_writer)
    monkeypatch.setattr(chaos_benchmark, "_mutator", fake_mutator)
    monkeypatch.setattr(chaos_benchmark, "_mutate_chain_hash_byte", fake_mutate)
    monkeypatch.setattr(chaos_benchmark, "verify_audit_file", fake_verify)

    mutations, _, detected, mode = chaos_benchmark._run_single_chaos(  # noqa: SLF001
        path=path,
        events=2,
        attestation_key="chaos-key",
        run_seed=9,
    )
    assert attempts["count"] == 8
    assert mutations == 0
    assert detected is True
    assert mode == "chain_validation"


def test_run_chaos_benchmark_handles_undetected_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_single(**_: object) -> tuple[int, float, bool, str]:
        return 1, 3.0, False, "none"

    monkeypatch.setattr(chaos_benchmark, "_run_single_chaos", fake_single)
    result = chaos_benchmark.run_chaos_benchmark(
        runs=2,
        events=8,
        seed=1337,
        p95_max_ms=200.0,
        p99_max_ms=250.0,
        workdir=tmp_path / "chaos",
        attestation_key="chaos-key",
    )
    assert result.detection_rate == 0.0
    assert result.passed is False
    assert all(item.detected is False for item in result.results)


def test_main_prints_text_summary_when_json_flag_is_absent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output_path = tmp_path / "chaos_metrics.json"
    code = chaos_benchmark.main(
        [
            "--runs",
            "3",
            "--events",
            "12",
            "--p95-max-ms",
            "200",
            "--p99-max-ms",
            "250",
            "--workdir",
            str(tmp_path / "chaos"),
            "--output",
            str(output_path),
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "chaos_benchmark passed=" in captured.out
