"""Public API for running rule engines. Delegates to checkov adapter for now."""

from __future__ import annotations

from pathlib import Path

from iac_scanner.models import Finding
from iac_scanner.rules.checkov import CheckovNotInstalled, checkov_available, run_checkov


class RuleEngineError(RuntimeError):
    """Generic rule-engine failure."""


class RuleEngineNotInstalled(RuleEngineError):
    """Rule engine binary not installed or not on PATH."""


def is_available(engine: str = "checkov") -> bool:
    """Return True if the named engine is runnable in this environment."""
    if engine in ("checkov", "auto"):
        return checkov_available()
    return False


def run_rule_engine(
    path: Path,
    iac_type: str,
    *,
    engine: str = "auto",
) -> list[Finding]:
    """Run the rule engine against `path` and return findings.

    `engine`:
      - 'auto'    — use Checkov if installed, else empty list
      - 'checkov' — hard-require Checkov; raise RuleEngineNotInstalled if missing
      - 'none'    — no-op (returns [])
    """
    if engine == "none":
        return []
    if engine in ("auto", "checkov"):
        try:
            return run_checkov(path, iac_type)
        except CheckovNotInstalled as e:
            if engine == "auto":
                return []
            raise RuleEngineNotInstalled(str(e)) from e
    raise RuleEngineError(f"Unknown rule engine: {engine}")
