"""Tests for rules/engine.py and full subprocess-mocked Checkov runs."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from iac_scanner.models import Finding, FindingSource, Severity
from iac_scanner.rules import (
    RuleEngineError,
    RuleEngineNotInstalled,
    available_engines,
    is_available,
    run_rule_engine,
)
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

    def test_auto_false_when_nothing_available(self) -> None:
        with (
            patch("iac_scanner.rules.engine.checkov_available", return_value=False),
            patch("iac_scanner.rules.engine._discover_plugins", return_value={}),
        ):
            assert is_available("auto") is False

    def test_plugin_name_respected(self) -> None:
        with (
            patch("iac_scanner.rules.engine.checkov_available", return_value=False),
            patch(
                "iac_scanner.rules.engine._discover_plugins",
                return_value={"cdk-nag": lambda p, t: []},
            ),
        ):
            assert is_available("cdk-nag") is True
            assert is_available("checkov") is False


class TestAvailableEngines:
    def test_lists_checkov_and_plugins(self) -> None:
        with (
            patch("iac_scanner.rules.engine.checkov_available", return_value=True),
            patch(
                "iac_scanner.rules.engine._discover_plugins",
                return_value={"cdk-nag": lambda p, t: [], "cdk-nag-v2": lambda p, t: []},
            ),
        ):
            names = available_engines()
        assert "checkov" in names
        assert "cdk-nag" in names

    def test_empty_when_nothing_installed(self) -> None:
        with (
            patch("iac_scanner.rules.engine.checkov_available", return_value=False),
            patch("iac_scanner.rules.engine._discover_plugins", return_value={}),
        ):
            assert available_engines() == []


class TestPluginDispatch:
    def _plugin_finding(self) -> Finding:
        return Finding(
            severity=Severity.HIGH,
            title="nag-finding",
            description="from plugin",
            location="index.ts:App/Stack",
            source=FindingSource.CDK_NAG,
            rule_id="AwsSolutions-S1",
        )

    def test_explicit_plugin_name_dispatches_to_plugin(self) -> None:
        plugin_finding = self._plugin_finding()
        plugin = MagicMock(return_value=[plugin_finding])
        with patch("iac_scanner.rules.engine._discover_plugins", return_value={"cdk-nag": plugin}):
            result = run_rule_engine(Path("."), "cdk", engine="cdk-nag")
        plugin.assert_called_once_with(Path("."), "cdk")
        assert result == [plugin_finding]

    def test_unknown_plugin_raises(self) -> None:
        with (
            patch("iac_scanner.rules.engine.checkov_available", return_value=False),
            patch("iac_scanner.rules.engine._discover_plugins", return_value={}),
        ):
            with pytest.raises(RuleEngineError, match="Unknown rule engine"):
                run_rule_engine(Path("."), "cdk", engine="cdk-nag")

    def test_plugin_not_installed_normalized(self) -> None:
        class DummyNotInstalled(RuntimeError):
            pass

        def broken_plugin(path: Path, iac_type: str) -> list[Finding]:
            raise DummyNotInstalled("cdk-nag not installed on PATH")

        with patch("iac_scanner.rules.engine._discover_plugins", return_value={"cdk-nag": broken_plugin}):
            with pytest.raises(RuleEngineNotInstalled):
                run_rule_engine(Path("."), "cdk", engine="cdk-nag")

    def test_auto_unions_checkov_and_plugin_findings(self) -> None:
        checkov_finding = Finding(
            severity=Severity.MEDIUM,
            title="checkov-finding",
            description="from checkov",
            location="main.tf:5",
            source=FindingSource.CHECKOV,
            rule_id="CKV_AWS_1",
        )
        plugin_finding = self._plugin_finding()
        with (
            patch("iac_scanner.rules.engine.checkov_available", return_value=True),
            patch("iac_scanner.rules.engine.run_checkov", return_value=[checkov_finding]),
            patch(
                "iac_scanner.rules.engine._discover_plugins",
                return_value={"cdk-nag": lambda p, t: [plugin_finding]},
            ),
        ):
            result = run_rule_engine(Path("."), "cdk", engine="auto")
        assert checkov_finding in result
        assert plugin_finding in result

    def test_auto_skips_broken_plugins(self) -> None:
        def crashing_plugin(path: Path, iac_type: str) -> list[Finding]:
            raise RuntimeError("something went wrong")

        with (
            patch("iac_scanner.rules.engine.checkov_available", return_value=False),
            patch("iac_scanner.rules.engine._discover_plugins", return_value={"broken": crashing_plugin}),
        ):
            # Should not raise — auto mode tolerates plugin failures
            assert run_rule_engine(Path("."), "cdk", engine="auto") == []


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
        # engine='auto' probes checkov_available before calling run_checkov,
        # so we need to patch both to keep the test hermetic (Checkov may or
        # may not actually be installed in the runner's venv).
        with (
            patch("iac_scanner.rules.engine.checkov_available", return_value=True),
            patch("iac_scanner.rules.engine.run_checkov", return_value=canned),
        ):
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
