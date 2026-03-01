# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-02-21

### Added

- Single source of truth for version (pyproject.toml); package reads via importlib.metadata.
- Pre-commit hook for version consistency check.
- Changelog and bump script for major/minor/patch (scripts/bump_version.py, make bump-*).

### Changed

- Version is no longer hardcoded in __init__.py or cli.py.

## [0.1.1] - (previous)

### Changed

- Version bump for PyPI re-upload.

## [0.1.0] - (initial)

### Added

- Initial release: Terraform and CDK scanners, LangChain orchestration, report and fixed code output.
