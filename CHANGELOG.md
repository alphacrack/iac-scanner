# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Versioning is now tag-driven via [setuptools-scm](https://setuptools-scm.readthedocs.io/).** The package version is derived from the latest signed annotated `vX.Y.Z` git tag. `pyproject.toml` no longer has a hardcoded `version = ...`; it uses `dynamic = ["version"]`. `iac_scanner.__version__` reads from `_version.py` (written at build time by setuptools-scm) and falls back to `importlib.metadata` for installed wheels.
- **Release flow is now `make release-{patch,minor,major}`.** The new `scripts/release.py` promotes `CHANGELOG.md [Unreleased]` → `[X.Y.Z]`, commits the change with DCO sign-off, and creates a GPG-signed annotated tag. Pushing the tag (`git push --follow-tags`) is the only step that triggers PyPI publish. The legacy `scripts/bump_version.py`, `scripts/check_version.py`, and the `check-version` pre-commit hook are removed.
- **CI workflows fetch full git history** (`fetch-depth: 0`) where they build distributions, so setuptools-scm sees the tags it needs.

### Added

- **`.github/workflows/release.yml`** — auto-creates a GitHub Release from the matching CHANGELOG section when a `vX.Y.Z` tag is pushed. Rejects lightweight tags. The `release: published` event then triggers the existing `publish-pypi.yml`.
- **`.github/workflows/scorecard.yml`** — OpenSSF Scorecard runs weekly + on push to `main`. Results posted to the Security tab and to scorecard.dev (badge in README).
- **`.github/workflows/codeql.yml`** — CodeQL static analysis (Python, `security-and-quality` query suite) on PR + weekly cron.
- **`GOVERNANCE.md`** — roles, decision-making, branch-protection policy, release authority.
- **`MAINTAINERS.md`** — canonical maintainer list (mirrors `.github/CODEOWNERS`).
- **`SUPPORT.md`** — routes users to bug/feature/security/discussion channels.
- **`scripts/apply_branch_protection.sh`** — `gh`-based, idempotent applier for the `main`-branch protection rules described in `GOVERNANCE.md`. Run from any maintainer's machine.
- **README badges:** Python versions, CodeQL, OpenSSF Scorecard, DCO.
- **Rule-engine plugin discovery.** Third-party rule engines can now register themselves via the `iac_scanner.rule_engines` entry-point group. Install e.g. [`iac-scanner-cdk-nag`](packages/iac-scanner-cdk-nag/) and the `cdk-nag` engine is auto-discovered — no core changes required. Core engine dispatcher in `src/iac_scanner/rules/engine.py`. New `available_engines()` helper lists every usable engine (built-in + plugins).
- **Companion package: `iac-scanner-cdk-nag`** (`packages/iac-scanner-cdk-nag/`). Independent PyPI package that shells out to `cdk synth`, parses AwsSolutions / HIPAA / NIST-800-53 / PCI-DSS nag annotations, and returns them as iac-scanner Findings. Released via a dedicated `publish-nag-pypi.yml` workflow on `nag-v*` tags.
- **PEP 561 `py.typed` marker** on `iac_scanner` — downstream packages (like the nag extension) and mypy in other repos now recognize this package as fully typed.

### Dependencies

This release rolls up a batch of Dependabot upgrades. None change runtime behavior, but consumers pinning by upper bound should be aware:

- `click>=8.3.3` (was `>=8.1.0`)
- `pydantic>=2.13.4` (was `>=2.0.0`)
- `mcp>=1.27.1` (`[mcp]` extra; was `>=1.0.0`)
- Dev: `pytest>=9.0.3`, `respx>=0.23.1`, `bandit>=1.9.4`, `pip-audit>=2.10.0`, `build>=1.5.0`
- Build: `setuptools>=82.0.1` + `setuptools-scm>=8` (new)
- GitHub Actions majors: `actions/checkout@v6`, `actions/setup-python@v6`, `actions/upload-artifact@v7`, `actions/download-artifact@v8`, `sigstore/gh-action-sigstore-python@v3.3.0`

## [0.4.0] - 2026-04-18

### Changed

- **License changed from "Personal Use License" to Apache-2.0.** This is a breaking licensing change intended to unblock adoption. All prior contributors retain their copyright; contributions from 0.4.0 forward are under Apache-2.0.
- PyPI classifier updated from `License :: Other/Proprietary License` to `License :: OSI Approved :: Apache Software License`.
- README updated to reflect Apache-2.0 and new "complements rule-based scanners" positioning.

### Added

- `NOTICE` file (Apache-2.0 attribution).
- Python 3.13 listed in classifiers.
- PEP 639-style `license = { text = "Apache-2.0" }` declaration in `pyproject.toml`.
- Optional dependency extras scaffolded: `[local]` (Ollama), `[github]` (GitHub Models), `[mcp]` (MCP server), `[rules]` (Checkov hybrid), `[all]`.
- `iac-scan-mcp` console script entry point (implementation in 1.0.0).
- `pytest` markers (`e2e`, `smoke`, `integration`), coverage config, strict `mypy` config, `bandit` config — all in `pyproject.toml`.
- Dev deps expanded: `pytest-cov`, `respx`, `mypy`, `bandit`, `pip-audit`, `cyclonedx-bom`.
- `tiktoken` added to runtime deps for upcoming cost-guardrail feature.

### Fixed

- Scrubbed 17 keyword-stuffed entries from `pyproject.toml` `keywords` (e.g. `azure-cdk`, `google-cdk`, `iac-scanner-langchain-orchestrated-agents-terraform-cdk-langchain`) — violated PyPI ToS and risked takedown.
- LangChain deps now pinned `>=0.3,<0.4` to guard against 0.4 breaking changes.

## [0.3.2] - 2026-02-28

### Changed

- Version bump for PyPI metadata refresh.

## [0.3.1] - 2026-02-25

### Added

- Jekyll-based docs site in `/docs/` (tutorial, blog, quickstart) published via GitHub Pages.
- Blog post: "Introducing iac-scanner" (2026-02-21).
- `blog-release.yml` GitHub workflow for changelog-driven blog publishing.

## [0.3.0] - 2026-02-22

### Added

- Initial docs/blog scaffolding (later split into 0.3.1).

## [0.2.1] - 2026-03-01

### Added

- Version bump to 0.2.1.
- Updated README and documentation.

## [0.2.0] - 2026-02-21

### Added

- Single source of truth for version (`pyproject.toml`); package reads via `importlib.metadata`.
- Pre-commit hook for version consistency check.
- Changelog and bump script for major/minor/patch (`scripts/bump_version.py`, `make bump-*`).

### Changed

- Version is no longer hardcoded in `__init__.py` or `cli.py`.

## [0.1.1] - (previous)

### Changed

- Version bump for PyPI re-upload.

## [0.1.0] - (initial)

### Added

- Initial release: Terraform and CDK scanners, LangChain orchestration, report and fixed code output.

---

## Roadmap

Items below are planned but not scheduled. They are intentionally kept out of `[Unreleased]` so they don't end up in release notes by accident. Once a roadmap item lands in a PR, move it to the matching subsection (`Added` / `Changed` / `Fixed`) under `[Unreleased]`.

### Planned for 1.0.0

- Pluggable LLM providers: OpenAI, Anthropic, GitHub Models (keyless for GitHub users), Ollama (local).
- MCP server mode (`iac-scan-mcp`): expose iac-scanner as tools to Claude Desktop / Cursor / Continue.dev — host app supplies the LLM, no API key required by iac-scanner.
- Checkov hybrid mode: rule-engine pre-pass + LLM augment + post-fix verification.
- SARIF 2.1.0 output format for GitHub Code Scanning / GitLab Security Dashboard.
- Content-addressed response cache with configurable TTL.
- Cost guardrail via `tiktoken` preflight + `--max-spend` flag.
- Prompt-injection mitigations: XML input fencing, secret redaction, default skip-list.
- Structured LLM output with Pydantic schemas (replaces regex-based JSON extraction).
- 80% test coverage target with mocked-LLM integration tests.
