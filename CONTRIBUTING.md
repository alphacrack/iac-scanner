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

| Command        | Description                    |
|----------------|--------------------------------|
| `make test`    | Run pytest                     |
| `make lint`    | Ruff check                     |
| `make fmt`     | Ruff format                    |
| `make check`   | Lint then test                 |
| `make build`   | Build sdist/wheel into `dist/` |
| `make clean`   | Remove caches and build artifacts |

Manual checks:

```bash
ruff check src/ tests/ && ruff format src/ tests/
pytest tests/ -v
```

---

## Versioning and releases

- We use **Semantic Versioning** (e.g. `v0.1.0`, `v0.2.0`).
- Releases are cut from `main` by creating a tag and (on GitHub) a **Release**:
  - `git tag v0.1.0 && git push origin v0.1.0`
  - Create a GitHub Release from that tag and publish it.
- **CI:** Lint and test run on push/PR (GitHub Actions and GitLab CI). On **published GitHub Release**, the workflow builds the package and **publishes to PyPI** (requires `PYPI_API_TOKEN` secret).

---

## Project layout

- `src/iac_scanner/` – main package (CLI, factory, scanners, orchestration, output).
- `tests/` – pytest tests (no API keys required for factory/scan tests).
- `samples/` – sample Terraform and CDK for manual and test use.

---

## License

By contributing, you agree that your contributions will be licensed under the same [Personal Use License](LICENSE) as the project. Redistribution of this project (or derivatives) still requires permission from the copyright holder(s).
