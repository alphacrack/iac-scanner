"""CLI entry: path to TF (main.tf) or CDK (index.ts), scan and output report + fixed code."""

import os
from pathlib import Path

import click

from iac_scanner import __version__
from iac_scanner.factory import create_scanner
from iac_scanner.orchestration.runner import run_pipeline
from iac_scanner.output.report import write_report_and_fixes


def _require_api_keys(need_fix: bool) -> None:
    """Ensure required API keys are set; exit with a clear message if not."""
    analysis_ai = os.environ.get("IAC_ANALYSIS_AI", "openai").lower()
    fix_ai = os.environ.get("IAC_FIX_AI", "openai").lower()
    missing = []
    if analysis_ai == "openai" and not os.environ.get("OPENAI_API_KEY"):
        missing.append("OPENAI_API_KEY")
    elif analysis_ai == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
        missing.append("ANTHROPIC_API_KEY")
    if need_fix:
        if fix_ai == "openai" and not os.environ.get("OPENAI_API_KEY"):
            if "OPENAI_API_KEY" not in missing:
                missing.append("OPENAI_API_KEY")
        elif fix_ai == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
            if "ANTHROPIC_API_KEY" not in missing:
                missing.append("ANTHROPIC_API_KEY")
    if missing:
        click.echo(
            "Missing API key(s): " + ", ".join(missing) + "\nSet the variable(s) or use --scan-only to run without AI.",
            err=True,
        )
        raise SystemExit(1)


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
    "--no-fix",
    is_flag=True,
    help="Only produce report; do not run fix step or write fixed code.",
)
@click.option(
    "--scan-only",
    is_flag=True,
    help="Only scan files and write report (no AI). Use to test without API keys.",
)
@click.option(
    "--analysis-ai",
    type=click.Choice(["openai", "anthropic"]),
    default=None,
    envvar="IAC_ANALYSIS_AI",
    help="AI for analysis task (env: IAC_ANALYSIS_AI)",
)
@click.option(
    "--fix-ai",
    type=click.Choice(["openai", "anthropic"]),
    default=None,
    envvar="IAC_FIX_AI",
    help="AI for fix/code-gen task (env: IAC_FIX_AI)",
)
def scan(
    path: Path,
    output_dir: Path | None,
    report_name: str,
    no_fix: bool,
    scan_only: bool,
    analysis_ai: str | None,
    fix_ai: str | None,
) -> None:
    """
    Scan IaC at PATH (Terraform: directory or file main.tf; CDK: directory or index.ts/index.js).
    Writes report and fixed code under OUTPUT_DIR.
    """
    if analysis_ai is not None:
        os.environ["IAC_ANALYSIS_AI"] = analysis_ai
    if fix_ai is not None:
        os.environ["IAC_FIX_AI"] = fix_ai

    try:
        scanner = create_scanner(path)
    except ValueError as e:
        click.echo(str(e), err=True)
        raise SystemExit(1)

    click.echo(f"Detected: {scanner.iac_type} (entry: {scanner.entry_path})")

    if not scan_only:
        _require_api_keys(need_fix=not no_fix)

    scan_result = scanner.scan()
    if scan_only:
        click.echo("Scan-only: writing report (no AI).")
        from iac_scanner.orchestration.runner import PipelineResult

        result = PipelineResult(
            scan_result=scan_result,
            findings_raw="[]",
            fixed_code="",
        )
    elif no_fix:
        click.echo("Running scan -> analysis (AI)...")
        if not scan_result.raw_content:
            click.echo("No content to analyze.", err=True)
            raise SystemExit(1)
        from iac_scanner.orchestration.runner import PipelineResult
        from iac_scanner.orchestration.tasks import run_analysis

        findings_raw = run_analysis(
            iac_type=scan_result.iac_type,
            entry_path=str(scan_result.entry_path),
            raw_content=scan_result.raw_content,
        )
        result = PipelineResult(
            scan_result=scan_result,
            findings_raw=findings_raw,
            fixed_code="",
        )
    else:
        click.echo("Running scan -> analysis (AI) -> fix (AI)...")
        result = run_pipeline(scanner)

    out = output_dir or (path if path.is_dir() else path.parent) / "scan-output"
    written = write_report_and_fixes(
        result,
        out,
        report_name=report_name,
        write_fixed=not no_fix and bool(result.fixed_code),
    )
    click.echo(f"Output written to: {out}")
    for p in written:
        click.echo(f"  - {p}")


if __name__ == "__main__":
    main()
