# IaC Scanner - build, install, test, version, clean
PYTHON ?= python3
PIP ?= pip

.PHONY: help venv install install-dev build test lint fmt check check-version bump-patch bump-minor bump-major clean clean-all install-hooks

help:
	@echo "Targets:"
	@echo "  make install-dev   - install package editable with dev deps"
	@echo "  make install       - install package editable, no dev deps"
	@echo "  make build         - build sdist and wheel into dist/"
	@echo "  make test          - run pytest"
	@echo "  make lint          - ruff check"
	@echo "  make fmt           - ruff format"
	@echo "  make check         - lint then test"
	@echo "  make check-version - ensure version in pyproject.toml matches package"
	@echo "  make bump-patch    - bump patch version, update CHANGELOG"
	@echo "  make bump-minor    - bump minor version, update CHANGELOG"
	@echo "  make bump-major    - bump major version, update CHANGELOG"
	@echo "  make install-hooks - install pre-commit hooks (version check + ruff)"
	@echo "  make clean         - remove caches, dist, egg-info, out dirs"
	@echo "  make clean-all     - clean + hint to uninstall package"

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

check-version:
	$(PYTHON) scripts/check_version.py

bump-patch:
	$(PYTHON) scripts/bump_version.py patch

bump-minor:
	$(PYTHON) scripts/bump_version.py minor

bump-major:
	$(PYTHON) scripts/bump_version.py major

install-hooks:
	$(PIP) install pre-commit
	pre-commit install

clean:
	rm -rf dist \
		src/*.egg-info \
		.pytest_cache .ruff_cache .cache \
		out out-cdk \
		htmlcov .coverage

clean-all: clean
	@echo "To uninstall: pip uninstall iac-scanner -y"
