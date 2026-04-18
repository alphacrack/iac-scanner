# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
