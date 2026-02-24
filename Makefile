.PHONY: fmt lint type test cov check

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
