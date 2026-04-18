"""Branch coverage tests for cli.py — error paths, fail-on, rules-engine wiring."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from iac_scanner.cli import _exit_code_for_findings, _resolve_provider, main
from iac_scanner.cost import CostBudgetExceeded
from iac_scanner.llm import ProviderError
from iac_scanner.models import Finding, FindingSource, Severity
from iac_scanner.orchestration.runner import PipelineResult
from iac_scanner.scanners._filters import InputTooLargeError
from iac_scanner.scanners.base import ScanResult

SAMPLES = Path(__file__).parent.parent / "samples"


class TestExitCodeForFindings:
    def test_none_threshold_always_passes(self) -> None:
        findings = [{"severity": "critical"}, {"severity": "high"}]
        assert _exit_code_for_findings(findings, "none") == 0

    def test_empty_findings_always_passes(self) -> None:
        assert _exit_code_for_findings([], "critical") == 0

    def test_fail_on_high_trips_on_high(self) -> None:
        assert _exit_code_for_findings([{"severity": "high"}], "high") == 1

    def test_fail_on_high_trips_on_critical(self) -> None:
        assert _exit_code_for_findings([{"severity": "critical"}], "high") == 1

    def test_fail_on_high_ignores_medium(self) -> None:
        assert _exit_code_for_findings([{"severity": "medium"}], "high") == 0

    def test_fail_on_low_trips_on_medium(self) -> None:
        assert _exit_code_for_findings([{"severity": "medium"}], "low") == 1

    def test_unknown_severity_does_not_crash(self) -> None:
        assert _exit_code_for_findings([{"severity": "mystery"}], "high") == 0

    def test_mixed_severities_return_nonzero_on_any_match(self) -> None:
        findings = [{"severity": "low"}, {"severity": "high"}, {"severity": "info"}]
        assert _exit_code_for_findings(findings, "high") == 1


class TestResolveProvider:
    def test_explicit_provider_wins(self) -> None:
        assert _resolve_provider("openai", None, None) == "openai"

    def test_auto_returns_none(self) -> None:
        assert _resolve_provider("auto", None, None) is None

    def test_none_provider_returns_none(self) -> None:
        assert _resolve_provider(None, None, None) is None

    def test_legacy_flags_warn_and_resolve(self) -> None:
        with pytest.warns(DeprecationWarning):
            assert _resolve_provider("auto", "anthropic", None) == "anthropic"

    def test_legacy_fix_ai_used_when_analysis_missing(self) -> None:
        with pytest.warns(DeprecationWarning):
            assert _resolve_provider("auto", None, "openai") == "openai"


class TestCliFailOn:
    def test_fail_on_high_exits_nonzero_when_high_finding_present(self, tmp_path: Path) -> None:
        """Route --fail-on through a pipeline that returns a HIGH finding via a mocked hybrid run."""
        mocked = PipelineResult(
            scan_result=ScanResult(
                iac_type="terraform",
                entry_path=SAMPLES / "tf" / "main.tf",
                raw_content="#",
            ),
            findings=[
                Finding(
                    severity=Severity.HIGH,
                    title="S3 public",
                    description="ACL public",
                    location="main.tf:1",
                    source=FindingSource.LLM,
                )
            ],
        )
        out_dir = tmp_path / "out"
        with (
            patch("iac_scanner.cli.auto_detect_provider", return_value="openai"),
            patch("iac_scanner.cli.run_pipeline", return_value=mocked),
        ):
            result = CliRunner().invoke(
                main,
                [
                    "scan",
                    str(SAMPLES / "tf"),
                    "-o",
                    str(out_dir),
                    "--provider",
                    "openai",
                    "--no-fix",
                    "--fail-on",
                    "high",
                ],
                env={"OPENAI_API_KEY": "sk-test"},
            )
        assert result.exit_code == 1
        assert "high" in (result.output).lower()

    def test_fail_on_none_exits_zero_even_with_high_findings(self, tmp_path: Path) -> None:
        mocked = PipelineResult(
            scan_result=ScanResult(
                iac_type="terraform",
                entry_path=SAMPLES / "tf" / "main.tf",
                raw_content="#",
            ),
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    title="crit",
                    description="d",
                    location="main.tf:1",
                    source=FindingSource.LLM,
                )
            ],
        )
        out_dir = tmp_path / "out"
        with (
            patch("iac_scanner.cli.auto_detect_provider", return_value="openai"),
            patch("iac_scanner.cli.run_pipeline", return_value=mocked),
        ):
            result = CliRunner().invoke(
                main,
                [
                    "scan",
                    str(SAMPLES / "tf"),
                    "-o",
                    str(out_dir),
                    "--provider",
                    "openai",
                    "--no-fix",
                    "--fail-on",
                    "none",
                ],
                env={"OPENAI_API_KEY": "sk-test"},
            )
        assert result.exit_code == 0


class TestCliRulesEngineRouting:
    def test_rules_engine_routes_through_hybrid(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "out"
        sentinel = PipelineResult(
            scan_result=ScanResult(
                iac_type="terraform",
                entry_path=SAMPLES / "tf" / "main.tf",
                raw_content="#",
            ),
            findings=[],
        )
        with (
            patch("iac_scanner.cli.auto_detect_provider", return_value="openai"),
            patch("iac_scanner.cli.run_hybrid_pipeline", return_value=sentinel) as hybrid_mock,
            patch("iac_scanner.cli.run_pipeline") as normal_mock,
        ):
            result = CliRunner().invoke(
                main,
                [
                    "scan",
                    str(SAMPLES / "tf"),
                    "-o",
                    str(out_dir),
                    "--provider",
                    "openai",
                    "--no-fix",
                    "--rules-engine",
                    "checkov",
                ],
                env={"OPENAI_API_KEY": "sk-test"},
            )
        assert result.exit_code == 0
        hybrid_mock.assert_called_once()
        normal_mock.assert_not_called()

    def test_no_rules_engine_uses_plain_pipeline(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "out"
        sentinel = PipelineResult(
            scan_result=ScanResult(
                iac_type="terraform",
                entry_path=SAMPLES / "tf" / "main.tf",
                raw_content="#",
            ),
            findings=[],
        )
        with (
            patch("iac_scanner.cli.auto_detect_provider", return_value="openai"),
            patch("iac_scanner.cli.run_pipeline", return_value=sentinel) as normal_mock,
            patch("iac_scanner.cli.run_hybrid_pipeline") as hybrid_mock,
        ):
            result = CliRunner().invoke(
                main,
                [
                    "scan",
                    str(SAMPLES / "tf"),
                    "-o",
                    str(out_dir),
                    "--provider",
                    "openai",
                    "--no-fix",
                ],
                env={"OPENAI_API_KEY": "sk-test"},
            )
        assert result.exit_code == 0
        normal_mock.assert_called_once()
        hybrid_mock.assert_not_called()


class TestCliErrorPaths:
    def test_cost_budget_exceeded_exits_2(self, tmp_path: Path) -> None:
        with (
            patch("iac_scanner.cli.auto_detect_provider", return_value="openai"),
            patch(
                "iac_scanner.cli.run_pipeline",
                side_effect=CostBudgetExceeded("projected $2 over $1 cap"),
            ),
        ):
            result = CliRunner().invoke(
                main,
                [
                    "scan",
                    str(SAMPLES / "tf"),
                    "-o",
                    str(tmp_path / "out"),
                    "--provider",
                    "openai",
                    "--no-fix",
                ],
                env={"OPENAI_API_KEY": "sk-test"},
            )
        assert result.exit_code == 2
        assert "cost guardrail" in result.output.lower()

    def test_input_too_large_exits_2(self, tmp_path: Path) -> None:
        with (
            patch("iac_scanner.cli.auto_detect_provider", return_value="openai"),
            patch(
                "iac_scanner.cli.run_pipeline",
                side_effect=InputTooLargeError("300KB > 200KB"),
            ),
        ):
            result = CliRunner().invoke(
                main,
                [
                    "scan",
                    str(SAMPLES / "tf"),
                    "-o",
                    str(tmp_path / "out"),
                    "--provider",
                    "openai",
                    "--no-fix",
                ],
                env={"OPENAI_API_KEY": "sk-test"},
            )
        assert result.exit_code == 2
        assert "input too large" in result.output.lower()

    def test_provider_error_exits_1(self, tmp_path: Path) -> None:
        with (
            patch("iac_scanner.cli.auto_detect_provider", return_value="openai"),
            patch(
                "iac_scanner.cli.run_pipeline",
                side_effect=ProviderError("no provider available"),
            ),
        ):
            result = CliRunner().invoke(
                main,
                [
                    "scan",
                    str(SAMPLES / "tf"),
                    "-o",
                    str(tmp_path / "out"),
                    "--provider",
                    "openai",
                    "--no-fix",
                ],
                env={"OPENAI_API_KEY": "sk-test"},
            )
        assert result.exit_code == 1
        assert "provider error" in result.output.lower()

    def test_scan_only_input_too_large_exits_2(self, tmp_path: Path) -> None:
        """Write a multi-KB main.tf so the 1KB floor on IAC_MAX_INPUT_BYTES trips."""
        big_dir = tmp_path / "big"
        big_dir.mkdir()
        (big_dir / "main.tf").write_text("# padding\n" * 500)  # ~5KB
        out_dir = tmp_path / "out"
        result = CliRunner().invoke(
            main,
            ["scan", str(big_dir), "-o", str(out_dir), "--scan-only"],
            env={"IAC_MAX_INPUT_BYTES": "1"},
        )
        assert result.exit_code == 2
        assert "input too large" in result.output.lower()

    def test_scan_unsupported_path_exits_1(self, tmp_path: Path) -> None:
        bogus = tmp_path / "nothing"
        bogus.mkdir()
        (bogus / "readme.md").write_text("hi")
        result = CliRunner().invoke(main, ["scan", str(bogus), "--scan-only"])
        assert result.exit_code == 1


class TestCliFlagPropagation:
    def test_no_cache_sets_env(self, tmp_path: Path) -> None:
        sentinel = PipelineResult(
            scan_result=ScanResult(
                iac_type="terraform",
                entry_path=SAMPLES / "tf" / "main.tf",
                raw_content="#",
            ),
            findings=[],
        )
        recorded: dict[str, str] = {}
        with (
            patch("iac_scanner.cli.auto_detect_provider", return_value="openai"),
            patch(
                "iac_scanner.cli.run_pipeline",
                side_effect=lambda *a, **k: (
                    recorded.update(
                        {
                            "IAC_NO_CACHE": __import__("os").environ.get("IAC_NO_CACHE", ""),
                            "IAC_MAX_SPEND_USD": __import__("os").environ.get("IAC_MAX_SPEND_USD", ""),
                        }
                    ),
                    sentinel,
                )[1],
            ),
        ):
            result = CliRunner().invoke(
                main,
                [
                    "scan",
                    str(SAMPLES / "tf"),
                    "-o",
                    str(tmp_path / "out"),
                    "--provider",
                    "openai",
                    "--no-fix",
                    "--no-cache",
                    "--max-spend",
                    "0.50",
                ],
                env={"OPENAI_API_KEY": "sk-test"},
            )
        assert result.exit_code == 0
        assert recorded["IAC_NO_CACHE"] == "1"
        assert recorded["IAC_MAX_SPEND_USD"] == "0.5"


class TestCliReportWriting:
    def test_scan_only_writes_expected_json_fields(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "out"
        result = CliRunner().invoke(
            main,
            ["scan", str(SAMPLES / "tf"), "-o", str(out_dir), "--scan-only"],
        )
        assert result.exit_code == 0
        data = json.loads((out_dir / "scan-report.json").read_text())
        assert data["iac_type"] == "terraform"
        assert "iac_scanner_version" in data
        assert "prompt_version" in data
