"""Rule-engine adapters — Checkov first, cdk-nag later.

The rule engine is an *optional* layer that grounds the LLM with deterministic,
framework-mapped findings. Install via `pip install iac-scanner[rules]`.

`run_rule_engine(path, iac_type, engine='auto')` is the public entry point.
`is_available(engine)` reports whether a given engine can run in this environment.
"""

from iac_scanner.rules.engine import (
    RuleEngineError,
    RuleEngineNotInstalled,
    is_available,
    run_rule_engine,
)

__all__ = [
    "RuleEngineError",
    "RuleEngineNotInstalled",
    "is_available",
    "run_rule_engine",
]
