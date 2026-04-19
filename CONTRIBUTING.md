# Contributing to IaC Scanner

This guide covers development setup, coding standards, and the release process. The README focuses on install and usage; this file is the single source for contribution and release workflow.

Contributions are welcome under [Apache License 2.0](LICENSE). By submitting a PR, you agree to license your contribution under Apache-2.0. Sign off with `git commit -s` (DCO).

---

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1). Report issues to `jha.bishwas@gmail.com`.

---

## How to contribute

1. **Open an issue** (bug or feature) so we can align before you invest time.
2. **Fork the repo** and create a branch from `development`: `git checkout -b fix/your-change`.
3. **Make your changes** and run locally (see [Development setup](#development-setup)).
4. **Push and open a Pull Request** targeting `development`. CI must pass.
5. **Sign off** commits with `-s` so DCO is satisfied (`git commit -s -m "..."`).

---

## Development setup

```bash
git clone https://github.com/alphacrack/iac-scanner
cd iac-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

**Useful commands:**

| Command                          | Description                                              |
|----------------------------------|----------------------------------------------------------|
| `pytest tests/ -m "not e2e"`     | Run the fast suite (unit + integration, mocked LLM)      |
| `pytest tests/ --cov=iac_scanner`| Run with coverage report                                 |
| `pytest tests/ -m e2e`           | Opt-in E2E against real LLM APIs (requires keys)         |
| `ruff check src/ tests/`         | Lint                                                     |
| `ruff format src/ tests/`        | Format                                                   |
| `mypy src/iac_scanner`           | Strict type check (CI hard-fails on any issue)           |
| `bandit -r src/ -ll -c pyproject.toml` | Security SAST                                      |
| `pip-audit`                      | Dependency CVE audit                                     |
| `pre-commit run --all-files`     | All pre-commit hooks (ruff, bandit, gitleaks, hygiene)   |
| `python -m build`                | Build sdist + wheel into `dist/`                         |
| `make bump-patch/minor/major`    | Bump version + add CHANGELOG section                     |

**Test markers:**

- `@pytest.mark.smoke` — fast CLI end-to-end, no keys needed.
- `@pytest.mark.integration` — mocked LLM via `FakeLLMClient` fixture.
- `@pytest.mark.e2e` — hits real provider APIs; only runs in the nightly workflow.

**Target coverage:** ≥ 90% line, ≥ 70% branch. CI currently enforces 80% with a plan to ratchet to 90%.

---

## CI gates

Every PR must pass:

- `ruff check` + `ruff format --check`
- `mypy --strict src/iac_scanner` (hard-fail)
- `pytest -m "not e2e"` with coverage on Python 3.10/3.11/3.12/3.13 × Ubuntu + macOS
- `bandit`, `ruff --select S`, `pip-audit`, `gitleaks`
- Smoke tests (CLI `--scan-only` on both samples)

See [.github/workflows/ci.yml](.github/workflows/ci.yml), [security.yml](.github/workflows/security.yml), and [nightly-e2e.yml](.github/workflows/nightly-e2e.yml).

---

## Blog and tutorial

The project blog and tutorial live in [docs/](docs/) and are published via GitHub Pages. To add a post, create `docs/_posts/YYYY-MM-DD-title.md` with Jekyll front-matter. The `blog-release.yml` workflow can auto-generate release posts from `CHANGELOG.md` — Actions → Blog release → Run workflow.

---

## Versioning and changelog

- **Single source of truth:** version lives only in `pyproject.toml`. The package reads it via `importlib.metadata`.
- **Pre-commit hook:** `check-version` verifies consistency.
- **Semver:** major = breaking API change (Apache-2.0 license change counted, back in v0.4.0); minor = new feature; patch = bug fix.
- **CHANGELOG:** [CHANGELOG.md](CHANGELOG.md) follows [Keep a Changelog](https://keepachangelog.com/). Update it with every PR that changes user-visible behavior.

---

## Releases

We use **Semantic Versioning** (`vMAJOR.MINOR.PATCH`).

1. Bump version: `make bump-patch` / `bump-minor` / `bump-major`.
2. Edit the new CHANGELOG section to describe user-visible changes.
3. Commit: `git commit -s -m "Release v0.X.Y"`.
4. Tag: `git tag v0.X.Y && git push origin v0.X.Y`.
5. Create a GitHub Release from that tag. This triggers [publish-pypi.yml](.github/workflows/publish-pypi.yml).

The publish workflow:

- Builds sdist + wheel and runs `twine check`.
- Generates a **CycloneDX SBOM** (`sbom.cdx.json`) of the package dependencies.
- Publishes to PyPI via **Trusted Publishing (OIDC)** — no long-lived API token needed.
- Signs all artifacts + SBOM with **Sigstore** and attaches signatures to the GitHub Release.

### Trusted Publishing setup (one-time)

Before the first release, configure PyPI Trusted Publishing for this repo:

1. On [PyPI → iac-scanner → Publishing → Add publisher](https://pypi.org/manage/project/iac-scanner/settings/publishing/):
   - Owner: `alphacrack`
   - Repository: `iac-scanner`
   - Workflow filename: `publish-pypi.yml`
   - Environment name: `release`
2. Create a GitHub **environment** named `release` (Settings → Environments → New). No protection rules required, but you can gate on reviewers if desired.
3. Remove any legacy `PYPI_API_TOKEN` secret — Trusted Publishing obsoletes it.

After that, every published GitHub Release kicks off the full publish + sign + SBOM pipeline.

---

## Dependency management

- **Dependabot** opens weekly PRs for pip + GitHub Actions updates (see [.github/dependabot.yml](.github/dependabot.yml)).
- LangChain major-version bumps (`0.x → 1.x`) are **ignored** by Dependabot — they require a coordinated port. See the `LLMClient` protocol in `src/iac_scanner/llm/providers.py` — the swap path is isolated to that file.

---

## Project layout

- `src/iac_scanner/` — main package (CLI, factory, scanners, orchestration, output, rules, llm, mcp_server).
- `tests/` — pytest suite (220 tests, 92% coverage; no keys needed for `-m "not e2e"`).
- `samples/` — sample Terraform and CDK projects for manual and test use.
- `docs/` — Jekyll site (tutorial, blog, keyless guide).
- `.github/workflows/` — ci.yml, security.yml, nightly-e2e.yml, publish-pypi.yml, blog-release.yml.

---

## License

By contributing, you agree that your contributions will be licensed under [Apache License 2.0](LICENSE). The project NOTICE file credits contributors and third-party deps; add yourself if you prefer.
