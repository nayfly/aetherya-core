from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_aetherya_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Every test starts with no AETHERYA_* variables set.

    Without this a test silently inherits whatever the developer exported, and
    the suite passes or fails depending on the shell it was launched from. That
    is worst for the people actually running the stack: an operator with
    AETHERYA_CONSOLE_API_KEY exported — which is how you run the console — saw
    two console tests fail on a clean checkout.

    Tests that need a variable set it themselves with monkeypatch, which still
    works: this only clears the ambient values first.
    """
    for name in [key for key in os.environ if key.startswith("AETHERYA_")]:
        monkeypatch.delenv(name, raising=False)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests that require model download (sentence-transformers).",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if not config.getoption("--run-slow"):
        skip = pytest.mark.skip(reason="slow test — add --run-slow to include")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip)
