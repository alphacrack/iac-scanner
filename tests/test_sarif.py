"""Unit tests for SARIF 2.1.0 emission."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from iac_scanner.cli import main
from iac_scanner.models import Finding, FindingSource, Severity
from iac_scanner.output.sarif import _parse_location, build_sarif, write_sarif

SAMPLES = Path(__file__).parent.parent / "samples"


def _f(**kw: object) -> Finding:
    """Factory for minimal Finding with sensible defaults."""
    kw.setdefault("severity", Severity.HIGH)
    kw.setdefault("title", "Test finding")
    kw.setdefault("description", "A test finding")
    kw.setdefault("location", "main.tf:12")
    kw.setdefault("source", FindingSource.LLM)
    return Finding(**kw)  # type: ignore[arg-type]


class TestParseLocation:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("main.tf:12", ("main.tf", 12, None, None)),
            ("main.tf:12-15", ("main.tf", 12, 15, None)),
            ("main.tf:12:4", ("main.tf", 12, None, 4)),
            ("src/infra/main.tf:12", ("src/infra/main.tf", 12, None, None)),
            ("main.tf", ("main.tf", None, None, None)),
            ("lib/demo-stack.ts:42", ("lib/demo-stack.ts", 42, None, None)),
            ("", (None, None, None, None)),
            ("resource aws_s3_bucket.x", (None, None, None, None)),
        ],
    )
    def test_parses_common_shapes(
        self, raw: str, expected: tuple[str | None, int | None, int | None, int | None]
    ) -> None:
        assert _parse_location(raw) == expected


class TestBuildSarif:
    def test_empty_findings_produces_valid_sarif(self) -> None:
        sarif = build_sarif([], tool_version="1.0.0", entry_path="main.tf", iac_type="terraform")
        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"].endswith("/sarif-schema-2.1.0.json")
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "iac-scanner"
        assert sarif["runs"][0]["tool"]["driver"]["version"] == "1.0.0"
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_severity_maps_to_sarif_level(self) -> None:
        sarif = build_sarif(
            [
                _f(severity=Severity.CRITICAL, title="c"),
                _f(severity=Severity.HIGH, title="h"),
                _f(severity=Severity.MEDIUM, title="m"),
                _f(severity=Severity.LOW, title="l"),
                _f(severity=Severity.INFO, title="i"),
            ],
            tool_version="1.0.0",
            entry_path="main.tf",
            iac_type="terraform",
        )
        levels = [r["level"] for r in sarif["runs"][0]["results"]]
        assert levels == ["error", "error", "warning", "note", "none"]

    def test_rule_id_from_explicit_or_slug(self) -> None:
        sarif = build_sarif(
            [
                _f(rule_id="CKV_AWS_20", title="S3 public ACL"),
                _f(title="IAM role too permissive"),  # no explicit rule_id → slug
            ],
            tool_version="1.0.0",
            entry_path="main.tf",
            iac_type="terraform",
        )
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert "CKV_AWS_20" in rule_ids
        assert any(rid.startswith("IAC-iam-role") for rid in rule_ids)

    def test_rules_are_deduplicated(self) -> None:
        sarif = build_sarif(
            [
                _f(rule_id="CKV_AWS_20", title="Duplicate"),
                _f(rule_id="CKV_AWS_20", title="Duplicate"),
                _f(rule_id="CKV_AWS_20", title="Duplicate"),
            ],
            tool_version="1.0.0",
            entry_path="main.tf",
            iac_type="terraform",
        )
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        results = sarif["runs"][0]["results"]
        assert len(results) == 3
        for r in results:
            assert r["ruleIndex"] == 0

    def test_cwe_and_framework_preserved_in_rule_properties(self) -> None:
        sarif = build_sarif(
            [_f(rule_id="CKV_AWS_20", cwe="CWE-732", framework="CIS AWS 1.20")],
            tool_version="1.0.0",
            entry_path="main.tf",
            iac_type="terraform",
        )
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["cwe"] == "CWE-732"
        assert rule["properties"]["framework"] == "CIS AWS 1.20"

    def test_region_includes_start_and_end_line(self) -> None:
        sarif = build_sarif(
            [_f(location="main.tf:12-15")],
            tool_version="1.0.0",
            entry_path="main.tf",
            iac_type="terraform",
        )
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 12
        assert region["endLine"] == 15

    def test_unparseable_location_falls_back_to_entry_file(self) -> None:
        sarif = build_sarif(
            [_f(location="resource aws_s3_bucket.x")],
            tool_version="1.0.0",
            entry_path="/abs/path/main.tf",
            iac_type="terraform",
        )
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "main.tf"


class TestWriteSarif:
    def test_writes_valid_json_to_disk(self, tmp_path: Path) -> None:
        target = tmp_path / "out" / "report.sarif"
        write_sarif(
            [_f()],
            target,
            tool_version="1.0.0",
            entry_path="main.tf",
            iac_type="terraform",
        )
        assert target.exists()
        data = json.loads(target.read_text())
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 1


class TestCliSarifFormat:
    def test_cli_format_sarif_emits_only_sarif(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "out"
        result = CliRunner().invoke(
            main,
            ["scan", str(SAMPLES / "tf"), "-o", str(out_dir), "--scan-only", "--format", "sarif"],
        )
        assert result.exit_code == 0, result.output
        assert (out_dir / "scan-report.sarif").exists()
        assert not (out_dir / "scan-report.json").exists()

    def test_cli_format_both_emits_both(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "out"
        result = CliRunner().invoke(
            main,
            ["scan", str(SAMPLES / "tf"), "-o", str(out_dir), "--scan-only", "--format", "both"],
        )
        assert result.exit_code == 0, result.output
        assert (out_dir / "scan-report.json").exists()
        assert (out_dir / "scan-report.sarif").exists()

    def test_cli_format_json_default(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "out"
        result = CliRunner().invoke(
            main,
            ["scan", str(SAMPLES / "tf"), "-o", str(out_dir), "--scan-only"],
        )
        assert result.exit_code == 0, result.output
        assert (out_dir / "scan-report.json").exists()
        assert not (out_dir / "scan-report.sarif").exists()
