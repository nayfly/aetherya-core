.PHONY: fmt lint type test cov check security_baseline

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
