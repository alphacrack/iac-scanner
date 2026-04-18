"""CLI entry: scan Terraform (main.tf) or CDK (index.ts/js), output report + fixed code.

v1.0 additions:
  --provider     one of openai|anthropic|github|ollama|auto  (replaces --analysis-ai/--fix-ai)
  --format       output format: json|sarif|both
  --no-cache     skip response cache for this run
  --max-spend    hard dollar cap for projected LLM cost
  --fail-on      exit-code policy: none|low|medium|high|critical
  --rules-engine checkov|cdk-nag|auto|none  (hybrid mode with rule-engine grounding)
"""

from __future__ import annotations

import os
import sys
import warnings
from pathlib import Path

import click

from iac_scanner import __version__
from iac_scanner.cost import CostBudgetExceeded
from iac_scanner.factory import create_scanner
from iac_scanner.llm import ProviderError, auto_detect_provider
from iac_scanner.orchestration.hybrid import run_hybrid_pipeline
from iac_scanner.orchestration.runner import PipelineResult, run_pipeline
from iac_scanner.output.report import write_report_and_fixes
from iac_scanner.scanners._filters import InputTooLargeError


def _resolve_provider(
    provider: str | None,
    analysis_ai: str | None,
    fix_ai: str | None,
) -> str | None:
    """Resolve the provider, honoring legacy flags with a deprecation warning.

    Returns None when the caller asked for `auto` so run_pipeline can auto-detect.
    """
    if provider and provider != "auto":
        return provider
    if analysis_ai or fix_ai:
        warnings.warn(
            "--analysis-ai and --fix-ai are deprecated; use --provider instead. v1.0 will require --provider.",
            DeprecationWarning,
            stacklevel=2,
        )
        return analysis_ai or fix_ai
    return None


def _exit_code_for_findings(findings: list[dict[str, object]], fail_on: str) -> int:
    """Return 0 for pass, 1 for fail based on the severity threshold."""
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = severity_rank.get(fail_on, -1)
    if threshold < 0:
        return 0
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if severity_rank.get(sev, -1) >= threshold:
            return 1
    return 0


@click.group()
@click.version_option(version=__version__, prog_name="iac-scan")
def main() -> None:
    """Scan Terraform (main.tf) or CDK (index.ts) IaC and output a report plus fixed code."""
    pass


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
)
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory for report and fixed code. Default: <path>/scan-output",
)
@click.option(
    "--report-name",
    default="scan-report.json",
    help="Report filename (default: scan-report.json)",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "sarif", "both"]),
    default="json",
    help="Output format for the report (default: json). SARIF 2.1.0 for GitHub Code Scanning.",
)
@click.option(
    "--no-fix",
    is_flag=True,
    help="Only produce report; do not run fix step or write fixed code.",
)
@click.option(
    "--scan-only",
    is_flag=True,
    help="Only scan files and write report (no AI). Use to test without provider keys.",
)
@click.option(
    "--provider",
    type=click.Choice(["openai", "anthropic", "github", "ollama", "auto"]),
    default="auto",
    envvar="IAC_PROVIDER",
    help="LLM provider. 'auto' picks from env: ollama → github → openai → anthropic.",
)
@click.option(
    "--analysis-ai",
    type=click.Choice(["openai", "anthropic"]),
    default=None,
    envvar="IAC_ANALYSIS_AI",
    help="[Deprecated] Use --provider. Legacy: AI for analysis task.",
)
@click.option(
    "--fix-ai",
    type=click.Choice(["openai", "anthropic"]),
    default=None,
    envvar="IAC_FIX_AI",
    help="[Deprecated] Use --provider. Legacy: AI for fix task.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    envvar="IAC_NO_CACHE",
    help="Skip the response cache; every run calls the LLM fresh.",
)
@click.option(
    "--max-spend",
    type=float,
    default=None,
    envvar="IAC_MAX_SPEND_USD",
    help="Hard dollar cap for projected LLM cost (pre-flight token estimate). Aborts if exceeded.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["none", "info", "low", "medium", "high", "critical"]),
    default="none",
    help="Exit non-zero if findings at this severity or above are present. Default: never fail on findings.",
)
@click.option(
    "--rules-engine",
    type=click.Choice(["checkov", "cdk-nag", "auto", "none"]),
    default="none",
    help="Rule-engine hybrid mode. 'auto' uses Checkov if installed. 'none' = LLM only.",
)
def scan(
    path: Path,
    output_dir: Path | None,
    report_name: str,
    output_format: str,
    no_fix: bool,
    scan_only: bool,
    provider: str,
    analysis_ai: str | None,
    fix_ai: str | None,
    no_cache: bool,
    max_spend: float | None,
    fail_on: str,
    rules_engine: str,
) -> None:
    """Scan IaC at PATH (Terraform directory/file main.tf; CDK directory/index.ts(js)).

    Writes report (JSON and/or SARIF) and fixed code under OUTPUT_DIR.
    """
    # Flags are wired but not all are fully implemented in this release. Note which:
    if no_cache:
        os.environ["IAC_NO_CACHE"] = "1"
    if max_spend is not None:
        os.environ["IAC_MAX_SPEND_USD"] = str(max_spend)
    if rules_engine != "none":
        os.environ["IAC_RULES_ENGINE"] = rules_engine
    if output_format in ("sarif", "both"):
        os.environ["IAC_OUTPUT_FORMAT"] = output_format

    try:
        scanner = create_scanner(path)
    except ValueError as e:
        click.echo(str(e), err=True)
        raise SystemExit(1) from e

    click.echo(f"Detected: {scanner.iac_type} (entry: {scanner.entry_path})")

    if scan_only:
        click.echo("Scan-only: writing report (no AI).")
        try:
            scan_result = scanner.scan()
        except InputTooLargeError as e:
            click.echo(f"Input too large: {e}", err=True)
            raise SystemExit(2) from e
        result = PipelineResult(scan_result=scan_result)
    else:
        resolved_provider = _resolve_provider(provider, analysis_ai, fix_ai)
        # Surface the resolved provider up front so the user knows what will be called.
        try:
            picked = resolved_provider or auto_detect_provider()
        except ProviderError as e:
            click.echo(str(e), err=True)
            raise SystemExit(1) from e
        click.echo(f"Provider: {picked}")

        stages = "scan -> analysis"
        if rules_engine != "none":
            stages = f"scan -> rule-engine({rules_engine}) -> analysis"
        if not no_fix:
            stages += " -> fix"
        click.echo(f"Running {stages}...")

        try:
            if rules_engine != "none":
                result = run_hybrid_pipeline(
                    scanner,
                    engine=rules_engine,
                    provider=picked,  # type: ignore[arg-type]
                    skip_fix=no_fix,
                )
            else:
                result = run_pipeline(
                    scanner,
                    provider=picked,  # type: ignore[arg-type]
                    skip_fix=no_fix,
                )
        except CostBudgetExceeded as e:
            click.echo(f"Cost guardrail: {e}", err=True)
            raise SystemExit(2) from e
        except InputTooLargeError as e:
            click.echo(f"Input too large: {e}", err=True)
            raise SystemExit(2) from e
        except ProviderError as e:
            click.echo(f"Provider error: {e}", err=True)
            raise SystemExit(1) from e

    out = output_dir or ((path if path.is_dir() else path.parent) / "scan-output")
    written = write_report_and_fixes(
        result,
        out,
        report_name=report_name,
        write_fixed=not no_fix and bool(result.fixed_code),
        output_format=output_format,
    )
    click.echo(f"Output written to: {out}")
    for p in written:
        click.echo(f"  - {p}")

    findings_dicts = result.findings_list
    click.echo(f"Findings: {len(findings_dicts)}")
    if result.cost_estimates and result.projected_cost_usd > 0:
        click.echo(
            f"Projected LLM cost: ${result.projected_cost_usd:.4f} "
            f"(cache hits: {result.cache_hits}/{len(result.cost_estimates) + result.cache_hits})"
        )

    # Exit non-zero if severity threshold is tripped.
    code = _exit_code_for_findings(findings_dicts, fail_on)
    if code != 0:
        click.echo(f"Exiting {code}: findings at or above '{fail_on}' severity.", err=True)
    sys.exit(code)


if __name__ == "__main__":
    main()
