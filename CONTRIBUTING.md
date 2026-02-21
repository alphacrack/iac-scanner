# Contributing to IaC Scanner

Thank you for considering contributing. Contributions are welcome under the terms of the [LICENSE](LICENSE) (personal use and contributing back to this project are permitted).

## Code of conduct

- Be respectful and constructive.
- Focus on the code and the problem, not the person.

## How to contribute

1. **Open an issue** (bug or feature) so we can align before you invest time.
2. **Fork the repo** and create a branch from `main`: `git checkout -b fix/your-change` or `feature/your-feature`.
3. **Make your changes** and run locally:
   ```bash
   pip install -e ".[dev]"
   ruff check src/ tests/ && ruff format src/ tests/
   pytest tests/ -v
   ```
4. **Push and open a Pull Request** (GitHub) or Merge Request (GitLab) targeting `main`.
5. **CI** must pass (lint + tests). A maintainer will review when possible.

## Versioning and releases

- We use **Semantic Versioning** (e.g. `v0.1.0`, `v0.2.0`).
- Releases are cut from `main` by tagging: `git tag v0.1.0 && git push origin v0.1.0`.
- CI builds artifacts on tags matching `v*.*.*` (GitLab and GitHub).

## Project layout

- `src/iac_scanner/` – main package (CLI, factory, scanners, orchestration, output).
- `tests/` – pytest tests (no API keys required for factory/scan tests).
- `samples/` – sample Terraform and CDK for manual and test use.

## License

By contributing, you agree that your contributions will be licensed under the same [Personal Use License](LICENSE) as the project. Redistribution of this project (or derivatives) still requires permission from the copyright holder(s).
