.PHONY: fmt lint type test cov check security_baseline chaos_benchmark pipeline_benchmark pipeline_memory_soak property_tests audit_fuzz openai_shadow_smoke pre_api_gate api_serve

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

pipeline_memory_soak:
	python scripts/pipeline_memory_soak.py --duration-sec 600 --runs 1 --corpus-size 100 --max-rss-growth-mb 128 --output audit/pipeline/pipeline_memory_soak.json

property_tests:
	pytest tests/test_risk_aggregator_property.py tests/test_chaos_benchmark.py -q

audit_fuzz:
	pytest tests/test_release_artifact_fuzz.py -q
	python -m aetherya.security_gate --phase2-mutation-rounds 64 --json > audit/security_gate/security_gate_fuzz64.json

openai_shadow_smoke:
	PYTHONPATH=src python scripts/openai_shadow_smoke.py --json

pre_api_gate:
	python scripts/pre_api_gate.py

api_serve:
	python -m aetherya.api_server --host 127.0.0.1 --port 8080

api_stop:
	@echo "Liberando puerto 8080..."
	-fuser -k 8080/tcp || true

api_restart: api_stop api_serve