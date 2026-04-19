"""Tests for the cdk-nag adapter."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from iac_scanner.models import FindingSource, Severity

from iac_scanner_cdk_nag.adapter import (
    CdkNagError,
    CdkNagNotInstalled,
    _framework_for,
    _parse_annotations,
    _severity_for,
    cdk_nag_available,
    run_cdk_nag,
)


def _fake_proc(stderr: str, stdout: str = "", returncode: int = 0) -> MagicMock:
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.stderr = stderr
    m.stdout = stdout
    m.returncode = returncode
    return m


class TestSeverityMapping:
    def test_warning_is_medium(self) -> None:
        assert _severity_for("AwsSolutions-EC23", "Warning") == Severity.MEDIUM

    def test_error_is_high_by_default(self) -> None:
        assert _severity_for("AwsSolutions-EC23", "Error") == Severity.HIGH

    def test_iam5_wildcard_is_critical(self) -> None:
        assert _severity_for("AwsSolutions-IAM5", "Error") == Severity.CRITICAL

    def test_s1_no_encryption_is_critical(self) -> None:
        assert _severity_for("AwsSolutions-S1", "Error") == Severity.CRITICAL


class TestFrameworkMapping:
    @pytest.mark.parametrize(
        "rule_id,expected",
        [
            ("AwsSolutions-IAM4", "AWS Well-Architected"),
            ("HIPAA.Security-SomeRule", "HIPAA Security Rule"),
            ("NIST800-53.R5-IAMPolicy", "NIST 800-53 rev 5"),
            ("NIST800-53.R4-Check", "NIST 800-53 rev 4"),
            ("PCI.DSS.321-CheckName", "PCI-DSS 3.2.1"),
            ("FedRAMP-Check", "FedRAMP"),
            ("UnknownRule-Foo", None),
        ],
    )
    def test_rule_id_maps_to_framework(self, rule_id: str, expected: str | None) -> None:
        assert _framework_for(rule_id) == expected


class TestAnnotationParsing:
    def test_parses_error_annotation(self) -> None:
        stderr = "[Error at /MyStack/Bucket/Resource] AwsSolutions-S1: The S3 Bucket has server access logs disabled."
        findings = _parse_annotations(stderr)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "AwsSolutions-S1"
        assert f.severity == Severity.CRITICAL
        assert f.source == FindingSource.CDK_NAG
        assert f.framework == "AWS Well-Architected"
        assert "logs disabled" in f.description
        assert "index.ts" in f.location

    def test_parses_warning_annotation(self) -> None:
        stderr = (
            "[Warning at /App/Stack/Func/Role/DefaultPolicy/Resource] AwsSolutions-IAM5: The IAM policy has wildcards."
        )
        findings = _parse_annotations(stderr)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_parses_multiple_annotations(self) -> None:
        stderr = "\n".join(
            [
                "[Error at /S/A] AwsSolutions-S1: no logging.",
                "[Warning at /S/B] AwsSolutions-IAM4: managed policies.",
                "[Error at /S/C] HIPAA.Security-S3DefaultEncryption: unencrypted.",
                "some noise line",
                "",
                "[Error at /S/D] NIST800-53.R5-IAMPolicy: overly broad.",
            ]
        )
        findings = _parse_annotations(stderr)
        assert len(findings) == 4
        ids = [f.rule_id for f in findings]
        assert ids == [
            "AwsSolutions-S1",
            "AwsSolutions-IAM4",
            "HIPAA.Security-S3DefaultEncryption",
            "NIST800-53.R5-IAMPolicy",
        ]

    def test_ignores_non_annotation_lines(self) -> None:
        stderr = "Starting synthesis...\nDone.\n"
        assert _parse_annotations(stderr) == []

    def test_empty_stderr_returns_empty(self) -> None:
        assert _parse_annotations("") == []


class TestRunCdkNag:
    def test_returns_empty_for_non_cdk_iac_type(self, tmp_path: Path) -> None:
        """Short-circuit when called against Terraform — dispatcher fans to all
        engines; non-cdk ones return empty cheaply.
        """
        assert run_cdk_nag(tmp_path, "terraform") == []

    def test_raises_when_cdk_not_installed(self, tmp_path: Path) -> None:
        with patch("iac_scanner_cdk_nag.adapter.shutil.which", return_value=None):
            with pytest.raises(CdkNagNotInstalled):
                run_cdk_nag(tmp_path, "cdk")

    def test_happy_path_returns_findings(self, tmp_path: Path) -> None:
        stderr = (
            "[Error at /App/MyStack/Bucket/Resource] AwsSolutions-S1: no logging.\n"
            "[Warning at /App/MyStack/Role/Policy] AwsSolutions-IAM5: wildcards.\n"
        )
        with (
            patch("iac_scanner_cdk_nag.adapter.shutil.which", return_value="/usr/local/bin/cdk"),
            patch(
                "iac_scanner_cdk_nag.adapter.subprocess.run",
                return_value=_fake_proc(stderr=stderr, returncode=1),
            ),
        ):
            findings = run_cdk_nag(tmp_path, "cdk")
        assert len(findings) == 2
        assert findings[0].rule_id == "AwsSolutions-S1"
        assert findings[1].rule_id == "AwsSolutions-IAM5"

    def test_synth_failure_without_annotations_raises(self, tmp_path: Path) -> None:
        """If cdk synth exits non-zero but produces no nag annotations, it's a
        real crash (TypeScript compile error, missing deps) — surface it."""
        with (
            patch("iac_scanner_cdk_nag.adapter.shutil.which", return_value="/usr/local/bin/cdk"),
            patch(
                "iac_scanner_cdk_nag.adapter.subprocess.run",
                return_value=_fake_proc(stderr="error TS2307: Cannot find module 'foo'", returncode=1),
            ),
        ):
            with pytest.raises(CdkNagError, match="cdk synth failed"):
                run_cdk_nag(tmp_path, "cdk")

    def test_synth_success_no_annotations_returns_empty(self, tmp_path: Path) -> None:
        """User hasn't wired cdk-nag aspects — not an error, just zero findings."""
        with (
            patch("iac_scanner_cdk_nag.adapter.shutil.which", return_value="/usr/local/bin/cdk"),
            patch(
                "iac_scanner_cdk_nag.adapter.subprocess.run",
                return_value=_fake_proc(stderr="", returncode=0),
            ),
        ):
            assert run_cdk_nag(tmp_path, "cdk") == []

    def test_timeout_raises(self, tmp_path: Path) -> None:
        with (
            patch("iac_scanner_cdk_nag.adapter.shutil.which", return_value="/usr/local/bin/cdk"),
            patch(
                "iac_scanner_cdk_nag.adapter.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="cdk", timeout=1),
            ),
        ):
            with pytest.raises(CdkNagError, match="timed out"):
                run_cdk_nag(tmp_path, "cdk", timeout_seconds=1)


class TestAvailable:
    def test_true_when_cdk_on_path(self) -> None:
        with patch("iac_scanner_cdk_nag.adapter.shutil.which", return_value="/usr/local/bin/cdk"):
            assert cdk_nag_available() is True

    def test_false_when_cdk_missing(self) -> None:
        with patch("iac_scanner_cdk_nag.adapter.shutil.which", return_value=None):
            assert cdk_nag_available() is False
