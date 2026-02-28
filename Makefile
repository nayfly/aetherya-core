.PHONY: fmt lint type test cov check security_baseline chaos_benchmark pipeline_benchmark

fmt:
	ruff format src tests
	black src tests

lint:
	ruff check src tests --fix

type:
	mypy src/aetherya

test:
	pytest

cov:
	pytest --cov

check: fmt lint type cov

security_baseline:
	python -m aetherya.security_baseline --baseline-path tests/fixtures/security_baseline/v1/stress_baseline.json

chaos_benchmark:
	python -m aetherya.chaos_benchmark --runs 25 --events 48 --seed 1337 --p95-max-ms 12 --p99-max-ms 20 --output audit/chaos/chaos_benchmark_metrics.json

pipeline_benchmark:
	python -m aetherya.pipeline_benchmark --runs 1 --corpus-size 100 --seed 1337 --p95-max-ms 10 --p99-max-ms 15 --output audit/pipeline/pipeline_benchmark_metrics.json
