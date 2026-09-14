# IaC Scanner - build, install, test, version, clean
PYTHON ?= python3
PIP ?= pip

.PHONY: help venv install install-dev build test lint fmt check version release-patch release-minor release-major release-dry clean clean-all install-hooks

help:
	@echo "Targets:"
	@echo "  make install-dev    - install package editable with dev deps"
	@echo "  make install        - install package editable, no dev deps"
	@echo "  make build          - build sdist and wheel into dist/"
	@echo "  make test           - run pytest"
	@echo "  make lint           - ruff check"
	@echo "  make fmt            - ruff format"
	@echo "  make check          - lint then test"
	@echo "  make version        - print the version setuptools-scm would emit"
	@echo "  make release-patch  - cut a patch release: promote CHANGELOG + signed tag"
	@echo "  make release-minor  - cut a minor release"
	@echo "  make release-major  - cut a major release"
	@echo "  make release-dry    - dry-run (preview a patch release; no writes)"
	@echo "  make install-hooks  - install pre-commit hooks (ruff + bandit + gitleaks + hygiene)"
	@echo "  make clean          - remove caches, dist, egg-info, out dirs"
	@echo "  make clean-all      - clean + hint to uninstall package"

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

# Print the version setuptools-scm would emit. Useful for verifying a tag is picked up correctly.
version:
	$(PYTHON) -c "from setuptools_scm import get_version; print(get_version(root='.'))"

release-patch:
	$(PYTHON) scripts/release.py patch

release-minor:
	$(PYTHON) scripts/release.py minor

release-major:
	$(PYTHON) scripts/release.py major

release-dry:
	$(PYTHON) scripts/release.py patch --dry-run

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
