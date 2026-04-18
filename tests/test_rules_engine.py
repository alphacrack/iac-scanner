"""Tests for rules/engine.py and full subprocess-mocked Checkov runs."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from iac_scanner.models import Finding, FindingSource
from iac_scanner.rules import RuleEngineError, RuleEngineNotInstalled, is_available, run_rule_engine
from iac_scanner.rules.checkov import CheckovError, CheckovNotInstalled, run_checkov

# ---- Fixture: a minimal Checkov JSON payload ----

CHECKOV_PAYLOAD = {
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_20",
                "check_name": "S3 Bucket has public ACL",
                "description": "The S3 bucket ACL allows public read access.",
                "severity": "HIGH",
                "file_path": "/main.tf",
                "file_line_range": [12, 18],
                "guideline": "Use bucket policies instead.",
            },
            {
                "check_id": "CKV_AWS_21",
                "check_name": "S3 encryption disabled",
                "description": "",
                "severity": "MEDIUM",
                "file_path": "/main.tf",
                "file_line_range": [20, 22],
            },
        ]
    }
}


def _fake_proc(stdout: str, returncode: int = 0) -> MagicMock:
    """Build a fake subprocess.CompletedProcess result."""
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.stdout = stdout
    m.stderr = ""
    m.returncode = returncode
    return m


class TestIsAvailable:
    def test_checkov_alias_is_auto(self) -> None:
        with patch("iac_scanner.rules.engine.checkov_available", return_value=True):
            assert is_available("checkov") is True
            assert is_available("auto") is True

    def test_false_for_unknown_engine(self) -> None:
        assert is_available("unknown-engine") is False


class TestRunRuleEngine:
    def test_engine_none_returns_empty(self) -> None:
        assert run_rule_engine(Path("."), "terraform", engine="none") == []

    def test_unknown_engine_raises(self) -> None:
        with pytest.raises(RuleEngineError, match="Unknown rule engine"):
            run_rule_engine(Path("."), "terraform", engine="pulumi-secure")

    def test_auto_returns_empty_when_unavailable(self) -> None:
        with patch(
            "iac_scanner.rules.engine.run_checkov",
            side_effect=CheckovNotInstalled("not found"),
        ):
            assert run_rule_engine(Path("."), "terraform", engine="auto") == []

    def test_checkov_explicit_raises_when_unavailable(self) -> None:
        with patch(
            "iac_scanner.rules.engine.run_checkov",
            side_effect=CheckovNotInstalled("not found"),
        ):
            with pytest.raises(RuleEngineNotInstalled):
                run_rule_engine(Path("."), "terraform", engine="checkov")

    def test_auto_delegates_to_checkov_when_available(self) -> None:
        canned = [
            Finding(
                severity="high",  # type: ignore[arg-type]
                title="t",
                description="d",
                location="main.tf:1",
                source=FindingSource.CHECKOV,
                rule_id="CKV_AWS_1",
            )
        ]
        with patch("iac_scanner.rules.engine.run_checkov", return_value=canned):
            result = run_rule_engine(Path("."), "terraform", engine="auto")
        assert result == canned


class TestRunCheckovHappyPath:
    def test_parses_single_framework_payload(self, tmp_path: Path) -> None:
        with (
            patch("iac_scanner.rules.checkov.checkov_available", return_value=True),
            patch("iac_scanner.rules.checkov.shutil.which", return_value="/usr/local/bin/checkov"),
            patch(
                "iac_scanner.rules.checkov.subprocess.run",
                return_value=_fake_proc(json.dumps(CHECKOV_PAYLOAD)),
            ),
        ):
            findings = run_checkov(tmp_path, "terraform")
        assert len(findings) == 2
        assert findings[0].rule_id == "CKV_AWS_20"
        assert findings[0].framework == "AWS"

    def test_parses_multi_framework_list_payload(self, tmp_path: Path) -> None:
        multi = [CHECKOV_PAYLOAD, CHECKOV_PAYLOAD]
        with (
            patch("iac_scanner.rules.checkov.checkov_available", return_value=True),
            patch("iac_scanner.rules.checkov.shutil.which", return_value="/usr/local/bin/checkov"),
            patch(
                "iac_scanner.rules.checkov.subprocess.run",
                return_value=_fake_proc(json.dumps(multi)),
            ),
        ):
            findings = run_checkov(tmp_path, "cdk")
        # 2 framework entries × 2 failed checks each
        assert len(findings) == 4

    def test_empty_stdout_returns_empty_list(self, tmp_path: Path) -> None:
        with (
            patch("iac_scanner.rules.checkov.checkov_available", return_value=True),
            patch("iac_scanner.rules.checkov.shutil.which", return_value="/usr/local/bin/checkov"),
            patch(
                "iac_scanner.rules.checkov.subprocess.run",
                return_value=_fake_proc("   "),
            ),
        ):
            findings = run_checkov(tmp_path, "terraform")
        assert findings == []

    def test_module_invocation_when_no_binary_on_path(self, tmp_path: Path) -> None:
        """If `checkov` isn't on PATH but the python package exists, we fall back to `python -m checkov.main`."""
        called: dict[str, object] = {}

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            called["cmd"] = cmd
            return _fake_proc(json.dumps(CHECKOV_PAYLOAD))

        with (
            patch("iac_scanner.rules.checkov.checkov_available", return_value=True),
            patch("iac_scanner.rules.checkov.shutil.which", return_value=None),
            patch("iac_scanner.rules.checkov.subprocess.run", side_effect=fake_run),
        ):
            run_checkov(tmp_path, "terraform")
        cmd = called["cmd"]
        assert isinstance(cmd, list)
        assert "-m" in cmd and "checkov.main" in cmd


class TestRunCheckovErrorPaths:
    def test_timeout_raises(self, tmp_path: Path) -> None:
        with (
            patch("iac_scanner.rules.checkov.checkov_available", return_value=True),
            patch("iac_scanner.rules.checkov.shutil.which", return_value="/usr/local/bin/checkov"),
            patch(
                "iac_scanner.rules.checkov.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="checkov", timeout=1),
            ),
        ):
            with pytest.raises(CheckovError, match="timed out"):
                run_checkov(tmp_path, "terraform", timeout_seconds=1)

    def test_file_not_found_raises_not_installed(self, tmp_path: Path) -> None:
        with (
            patch("iac_scanner.rules.checkov.checkov_available", return_value=True),
            patch("iac_scanner.rules.checkov.shutil.which", return_value="/usr/local/bin/checkov"),
            patch(
                "iac_scanner.rules.checkov.subprocess.run",
                side_effect=FileNotFoundError("missing"),
            ),
        ):
            with pytest.raises(CheckovNotInstalled):
                run_checkov(tmp_path, "terraform")

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        with (
            patch("iac_scanner.rules.checkov.checkov_available", return_value=True),
            patch("iac_scanner.rules.checkov.shutil.which", return_value="/usr/local/bin/checkov"),
            patch(
                "iac_scanner.rules.checkov.subprocess.run",
                return_value=_fake_proc("not-json ))) {{{"),
            ),
        ):
            with pytest.raises(CheckovError, match="parse"):
                run_checkov(tmp_path, "terraform")

    def test_scalar_payload_returns_empty(self, tmp_path: Path) -> None:
        with (
            patch("iac_scanner.rules.checkov.checkov_available", return_value=True),
            patch("iac_scanner.rules.checkov.shutil.which", return_value="/usr/local/bin/checkov"),
            patch(
                "iac_scanner.rules.checkov.subprocess.run",
                return_value=_fake_proc('"not a dict or list"'),
            ),
        ):
            assert run_checkov(tmp_path, "terraform") == []
