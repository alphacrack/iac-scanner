# Contributing to IaC Scanner

This guide is for anyone contributing code, docs, or issues. The README (and PyPI page) focus on install and usage; **this file is the single place for contribution and release process**.

Contributions are welcome under the [LICENSE](LICENSE) (personal use and contributing back to this project are permitted).

---

## Code of conduct

- Be respectful and constructive.
- Focus on the code and the problem, not the person.

---

## How to contribute

1. **Open an issue** (bug or feature) so we can align before you invest time.
2. **Fork the repo** and create a branch from `main`: `git checkout -b fix/your-change` or `feature/your-feature`.
3. **Make your changes** and run locally (see [Development setup](#development-setup)).
4. **Push and open a Pull Request** (GitHub) or Merge Request (GitLab) targeting `main`.
5. **CI** must pass (lint + tests). A maintainer will review when possible.

---

## Development setup

Clone the repo, then:

```bash
make install-dev    # editable install with dev deps (pytest, ruff, build)
# or
pip install -e ".[dev]"
```

**Useful commands:**

| Command            | Description                              |
|--------------------|------------------------------------------|
| `make test`        | Run pytest                               |
| `make lint`        | Ruff check                               |
| `make fmt`         | Ruff format                              |
| `make check`       | Lint then test                           |
| `make check-version` | Ensure version matches pyproject.toml  |
| `make bump-patch`  | Bump patch, update CHANGELOG              |
| `make bump-minor`  | Bump minor, update CHANGELOG              |
| `make bump-major`  | Bump major, update CHANGELOG              |
| `make install-hooks` | Install pre-commit (version + ruff)     |
| `make build`       | Build sdist/wheel into `dist/`           |
| `make clean`       | Remove caches and build artifacts         |

After cloning, run `make install-hooks` to install the pre-commit hook (version consistency check + ruff). Version is **single-sourced** in `pyproject.toml`; the package reads it via `importlib.metadata`. To release a new version, use `make bump-patch`, `make bump-minor`, or `make bump-major`, then edit the new CHANGELOG section and tag/release.

Manual checks:

```bash
ruff check src/ tests/ && ruff format src/ tests/
pytest tests/ -v
```

---

## Blog and tutorials

The project blog and tutorial live in the **`docs/`** directory and are published via **GitHub Pages** (enable in Settings → Pages, source: main / docs). New posts and tutorial "What's new" sections are created by running the **Actions → Blog release** workflow manually: open the **Actions** tab, select **Blog release**, click **Run workflow**, then enter the version (e.g. `0.2.1`) and optionally a post title and one-line summary. The workflow generates a new post from `CHANGELOG.md` and appends a subsection to the tutorial, then pushes to trigger a Pages deploy.

## Versioning and changelog

- **Single source of truth:** Version is only in `pyproject.toml`. The package exposes it via `importlib.metadata` (no hardcoded version in code).
- **Pre-commit:** The `check-version` hook ensures the installed package version matches `pyproject.toml` (run `make install-hooks`).
- **Bumping:** Use `make bump-patch`, `make bump-minor`, or `make bump-major`. Each updates `pyproject.toml` and adds a new section to `CHANGELOG.md` (edit the new section to describe changes).
- **Changelog:** [CHANGELOG.md](CHANGELOG.md) follows [Keep a Changelog](https://keepachangelog.com/). Maintain it when releasing.

## Releases

- We use **Semantic Versioning** (e.g. `v0.2.0`).
- Cut a release: bump version (`make bump-*`), edit CHANGELOG, commit, then create a tag and (on GitHub) a **Release**:
  - `git tag v0.2.0 && git push origin v0.2.0`
  - Create a GitHub Release from that tag and publish it.
- **CI:** Lint and test run on push/PR. On **published GitHub Release**, the workflow publishes to PyPI (requires `PYPI_API_TOKEN` secret).

### Trusted Publishing (PyPI)

Using [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) avoids storing a long-lived API token and improves supply-chain credibility. To enable it:

1. On **PyPI**: open the project → **Publishing** → **Add a new pending publisher**.
2. Choose **GitHub** as the provider, select this repository (e.g. `bishwasjha/iac-scanner`), set the **Workflow name** to `publish-pypi.yml`, and set the **Environment** if you use one (optional).
3. Add the publisher and approve any pending prompt on the PyPI side.
4. In the repo workflow [.github/workflows/publish-pypi.yml](.github/workflows/publish-pypi.yml), you can then use `pypa/gh-action-pypi-publish` without passing `password: ${{ secrets.PYPI_API_TOKEN }}` (the action will use OIDC). Once Trusted Publishing is working, you can remove or stop maintaining the `PYPI_API_TOKEN` secret for uploads.

---

## Project layout

- `src/iac_scanner/` – main package (CLI, factory, scanners, orchestration, output).
- `tests/` – pytest tests (no API keys required for factory/scan tests).
- `samples/` – sample Terraform and CDK for manual and test use.

---

## License

By contributing, you agree that your contributions will be licensed under the same [Personal Use License](LICENSE) as the project. Redistribution of this project (or derivatives) still requires permission from the copyright holder(s).
