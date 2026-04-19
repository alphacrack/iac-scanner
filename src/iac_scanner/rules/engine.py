"""Rule-engine dispatcher.

Built-in engine: `checkov` (Python). Shipped in the core package.

Third-party engines: discovered via the `iac_scanner.rule_engines` entry-point
group. Installing `iac-scanner-cdk-nag` (or any future adapter) makes a new
engine name available automatically — no changes to this file required.

Plugin contract:
    entry_point value resolves to a callable:
        (path: pathlib.Path, iac_type: str) -> list[Finding]
    If the underlying tool isn't installed the plugin should raise a
    `*NotInstalled` exception (anything inheriting from RuntimeError); the
    dispatcher handles the `engine="auto"` fall-through.
"""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import entry_points
from pathlib import Path

from iac_scanner.models import Finding
from iac_scanner.rules.checkov import CheckovNotInstalled, checkov_available, run_checkov

RuleEnginePlugin = Callable[[Path, str], list[Finding]]
_ENTRY_POINT_GROUP = "iac_scanner.rule_engines"


class RuleEngineError(RuntimeError):
    """Generic rule-engine failure."""


class RuleEngineNotInstalled(RuleEngineError):
    """Rule engine binary/package not installed or not on PATH."""


def _discover_plugins() -> dict[str, RuleEnginePlugin]:
    """Return a {name: callable} map for every registered plugin engine.

    Load failures are logged and skipped so a broken plugin doesn't take down
    the whole scanner. This is called lazily on each dispatch — the cost is
    negligible and it avoids stale caches during long-running processes.
    """
    discovered: dict[str, RuleEnginePlugin] = {}
    eps = entry_points(group=_ENTRY_POINT_GROUP)
    for ep in eps:
        try:
            discovered[ep.name] = ep.load()
        except Exception:  # noqa: BLE001 — plugin load mustn't brick the scanner
            import logging

            logging.getLogger(__name__).warning("Failed to load rule-engine plugin %r", ep.name, exc_info=True)
    return discovered


def is_available(engine: str = "checkov") -> bool:
    """Return True if the named engine can run in this environment.

    'auto' is available whenever at least one engine (built-in or plugin) is.
    """
    if engine == "auto":
        return checkov_available() or bool(_discover_plugins())
    if engine == "checkov":
        return checkov_available()
    plugins = _discover_plugins()
    return engine in plugins


def available_engines() -> list[str]:
    """Return the list of engine names currently usable — useful for CLI help."""
    names: list[str] = []
    if checkov_available():
        names.append("checkov")
    names.extend(_discover_plugins().keys())
    return names


def run_rule_engine(
    path: Path,
    iac_type: str,
    *,
    engine: str = "auto",
) -> list[Finding]:
    """Run the named engine against `path` and return findings.

    Accepted values:
        'none'     — no-op (returns [])
        'checkov'  — built-in; raises RuleEngineNotInstalled if Checkov missing
        '<plugin>' — any plugin name registered under iac_scanner.rule_engines
        'auto'     — try Checkov, then each plugin in discovery order; union
                     the findings they produce, skipping engines that aren't
                     installed. Never raises on missing engines.
    """
    if engine == "none":
        return []

    plugins = _discover_plugins()

    if engine == "auto":
        findings: list[Finding] = []
        if checkov_available():
            try:
                findings.extend(run_checkov(path, iac_type))
            except CheckovNotInstalled:
                # Race between availability probe and execution; ignore.
                pass
        for plugin_name, plugin in plugins.items():
            try:
                findings.extend(plugin(path, iac_type))
            except RuntimeError:
                # Plugin-specific NotInstalled / transient failure — skip in auto.
                continue
            except Exception:  # noqa: BLE001
                import logging

                logging.getLogger(__name__).warning(
                    "Plugin %r raised unexpectedly; skipping", plugin_name, exc_info=True
                )
        return findings

    if engine == "checkov":
        try:
            return run_checkov(path, iac_type)
        except CheckovNotInstalled as e:
            raise RuleEngineNotInstalled(str(e)) from e

    if engine in plugins:
        try:
            return plugins[engine](path, iac_type)
        except RuntimeError as e:
            # Plugins raise their own NotInstalled subclasses — normalize here.
            if "not installed" in str(e).lower() or "not found" in str(e).lower():
                raise RuleEngineNotInstalled(str(e)) from e
            raise

    raise RuleEngineError(
        f"Unknown rule engine: {engine!r}. Built-ins: checkov. Installed plugins: {list(plugins) or 'none'}."
    )
