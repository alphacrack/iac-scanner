"""Unit tests for mcp_server.py tool bodies.

The async server loop and MCP SDK integration are out of scope here — we just
verify each tool body returns the expected shape for both happy and error paths.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from iac_scanner.mcp_server import _tool_run_rule_engine, _tool_scan_iac_path

SAMPLES = Path(__file__).parent.parent / "samples"


class TestScanIacPath:
    def test_scans_terraform_sample(self) -> None:
        result = _tool_scan_iac_path(str(SAMPLES / "tf"))
        assert result["iac_type"] == "terraform"
        assert "main.tf" in result["entry_path"]
        assert "raw_content" in result
        assert "metadata" in result
        assert "error" not in result

    def test_scans_cdk_sample(self) -> None:
        result = _tool_scan_iac_path(str(SAMPLES / "cdk"))
        assert result["iac_type"] == "cdk"
        assert "error" not in result

    def test_empty_path_returns_error(self) -> None:
        result = _tool_scan_iac_path("")
        assert "error" in result

    def test_nonexistent_path_returns_error(self) -> None:
        result = _tool_scan_iac_path("/does/not/exist")
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_unsupported_path_returns_error(self, tmp_path: Path) -> None:
        # A plain directory with no main.tf/index.ts
        (tmp_path / "readme.md").write_text("hi")
        result = _tool_scan_iac_path(str(tmp_path))
        assert "error" in result


class TestRunRuleEngine:
    def test_missing_args_returns_error(self) -> None:
        assert "error" in _tool_run_rule_engine("", "")
        assert "error" in _tool_run_rule_engine("x", "")
        assert "error" in _tool_run_rule_engine("", "terraform")

    def test_checkov_absent_returns_install_hint(self) -> None:
        with patch("iac_scanner.mcp_server.is_available", return_value=False):
            result = _tool_run_rule_engine(str(SAMPLES / "tf"), "terraform")
        assert "error" in result
        assert "iac-scanner[rules]" in result["error"]

    def test_checkov_returns_findings_when_installed(self) -> None:
        with (
            patch("iac_scanner.mcp_server.is_available", return_value=True),
            patch(
                "iac_scanner.mcp_server.run_rule_engine",
                return_value=[],  # Empty list is a valid response
            ),
        ):
            result = _tool_run_rule_engine(str(SAMPLES / "tf"), "terraform")
        assert "findings" in result
        assert result["count"] == 0

    def test_checkov_failure_surfaces_error(self) -> None:
        with (
            patch("iac_scanner.mcp_server.is_available", return_value=True),
            patch(
                "iac_scanner.mcp_server.run_rule_engine",
                side_effect=RuntimeError("checkov crashed"),
            ),
        ):
            result = _tool_run_rule_engine(str(SAMPLES / "tf"), "terraform")
        assert "error" in result
        assert "checkov" in result["error"].lower()
