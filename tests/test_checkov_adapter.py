"""Unit tests for rules/checkov.py — payload adaptation + availability probing."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from iac_scanner.models import FindingSource, Severity
from iac_scanner.rules.checkov import (
    CheckovNotInstalled,
    _adapt_check,
    _cwe_hint,
    _extract_failed_checks,
    _framework_hint,
    checkov_available,
    run_checkov,
)


class TestAdaptCheck:
    def test_maps_severity_title_and_location(self) -> None:
        payload = {
            "check_id": "CKV_AWS_20",
            "check_name": "S3 Bucket has public ACL",
            "description": "The S3 bucket ACL allows public read access.",
            "severity": "HIGH",
            "file_path": "/main.tf",
            "file_line_range": [12, 18],
            "guideline": "Remove public-read ACL and use bucket policies instead.",
        }
        f = _adapt_check(payload)
        assert f.severity == Severity.HIGH
        assert f.title == "S3 Bucket has public ACL"
        assert f.location == "main.tf:12"
        assert f.source == FindingSource.CHECKOV
        assert f.rule_id == "CKV_AWS_20"
        assert f.framework == "AWS"
        assert f.remediation is not None and "public-read" in f.remediation

    def test_unknown_severity_defaults_medium(self) -> None:
        payload = {"check_id": "CKV_FOO_1", "check_name": "x", "severity": "XYZ"}
        assert _adapt_check(payload).severity == Severity.MEDIUM

    def test_missing_line_range_produces_file_only_location(self) -> None:
        payload = {"check_id": "CKV_AWS_1", "check_name": "x", "file_path": "/main.tf"}
        assert _adapt_check(payload).location == "main.tf"


class TestFrameworkHint:
    @pytest.mark.parametrize(
        "check_id,expected",
        [
            ("CKV_AWS_20", "AWS"),
            ("CKV_AZURE_1", "Azure"),
            ("CKV_GCP_5", "GCP"),
            ("CKV_K8S_10", "Kubernetes"),
            ("CKV_DOCKER_2", "Docker"),
            ("CKV2_AWS_1", "AWS"),
            ("CKV_GENERAL", None),
            ("", None),
        ],
    )
    def test_extracts_framework(self, check_id: str, expected: str | None) -> None:
        assert _framework_hint(check_id) == expected


class TestCweHint:
    def test_finds_cwe_key(self) -> None:
        assert _cwe_hint({"cwe": "CWE-732"}) == "CWE-732"

    def test_finds_cwe_id_key(self) -> None:
        assert _cwe_hint({"cwe_id": "CWE-284"}) == "CWE-284"

    def test_missing_returns_none(self) -> None:
        assert _cwe_hint({}) is None


class TestExtractFailedChecks:
    def test_extracts_from_standard_payload(self) -> None:
        payload = {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "check_name": "S3 public",
                        "severity": "HIGH",
                        "file_path": "/main.tf",
                        "file_line_range": [10, 12],
                    },
                    {
                        "check_id": "CKV_AWS_21",
                        "check_name": "S3 encryption",
                        "severity": "MEDIUM",
                        "file_path": "/main.tf",
                        "file_line_range": [20, 22],
                    },
                ]
            }
        }
        findings = _extract_failed_checks(payload)
        assert len(findings) == 2
        assert findings[0].rule_id == "CKV_AWS_20"
        assert findings[1].severity == Severity.MEDIUM

    def test_empty_payload_returns_empty_list(self) -> None:
        assert _extract_failed_checks({}) == []
        assert _extract_failed_checks({"results": {}}) == []
        assert _extract_failed_checks({"results": {"failed_checks": []}}) == []


class TestCheckovAvailable:
    def test_returns_true_when_binary_on_path(self) -> None:
        with patch("iac_scanner.rules.checkov.shutil.which", return_value="/usr/local/bin/checkov"):
            assert checkov_available() is True


class TestRunCheckovNotInstalled:
    def test_raises_when_unavailable(self) -> None:
        with patch("iac_scanner.rules.checkov.checkov_available", return_value=False):
            with pytest.raises(CheckovNotInstalled):
                from pathlib import Path

                run_checkov(Path("."), "terraform")
