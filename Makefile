# IaC Scanner - build, install, test, clean
PYTHON ?= python3
PIP ?= pip

.PHONY: help venv install install-dev build test lint fmt check clean clean-all

help:
	@echo "Targets:"
	@echo "  make install-dev  - install package editable with dev deps (pytest, ruff, build)"
	@echo "  make install      - install package editable, no dev deps"
	@echo "  make build        - build sdist and wheel into dist/"
	@echo "  make test         - run pytest"
	@echo "  make lint         - ruff check"
	@echo "  make fmt          - ruff format"
	@echo "  make check        - lint then test"
	@echo "  make clean        - remove caches, dist, egg-info, out dirs"
	@echo "  make clean-all    - clean + hint to uninstall package"

venv:
	@echo "Create venv: python3 -m venv .venv && source .venv/bin/activate"

install-dev:
	$(PIP) install -e ".[dev]"

install:
	$(PIP) install -e .

build:
	$(PIP) install build
	$(PYTHON) -m build --outdir dist/

test:
	$(PYTHON) -m pytest tests/ -v --tb=short

lint:
	ruff check src/ tests/

fmt:
	ruff format src/ tests/

check: lint test

clean:
	rm -rf dist \
		src/*.egg-info \
		.pytest_cache .ruff_cache .cache \
		out out-cdk \
		htmlcov .coverage

clean-all: clean
	@echo "To uninstall: pip uninstall iac-scanner -y"
