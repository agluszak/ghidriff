UV ?= uv

.PHONY: install install-dev dev-setup test test-fast test-integration lint format clean check

install:
	$(UV) sync --locked

install-dev:
	$(UV) sync --locked --extra testing --extra dev

dev-setup: install-dev
	$(UV) run --locked --extra testing --extra dev python tests/init_pyghidra.py

test:
	$(UV) run --locked --extra testing pytest

test-fast:
	$(UV) run --locked --extra testing pytest -m fast

test-integration:
	$(UV) run --locked --extra testing pytest -m integration

lint:
	$(UV) run --locked --extra dev ruff check ghidriff tests

format:
	$(UV) run --locked --extra dev ruff format ghidriff tests

check: lint test-fast

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find ghidriff tests -type d -name __pycache__ -prune -exec rm -rf {} +
