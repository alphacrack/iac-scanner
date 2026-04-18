"""Smoke tests: exercise the CLI end-to-end without calling any LLM.

These use Click's CliRunner for in-process testing — no subprocess cost,
deterministic, and safe to run in CI without any API keys.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from iac_scanner import __version__
from iac_scanner.cli import main

SAMPLES = Path(__file__).parent.parent / "samples"


@pytest.mark.smoke
def test_cli_version_prints_version() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


@pytest.mark.smoke
def test_cli_help_mentions_scan_command() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output.lower()


@pytest.mark.smoke
def test_cli_scan_only_terraform(tmp_path: Path) -> None:
    out_dir = tmp_path / "out-tf"
    result = CliRunner().invoke(
        main,
        ["scan", str(SAMPLES / "tf"), "-o", str(out_dir), "--scan-only"],
    )
    assert result.exit_code == 0, result.output
    report = out_dir / "scan-report.json"
    assert report.exists()
    data = json.loads(report.read_text())
    assert data["iac_type"] == "terraform"
    assert "main.tf" in str(data["entry_path"])
    assert "metadata" in data
    assert "files" in data["metadata"]


@pytest.mark.smoke
def test_cli_scan_only_cdk(tmp_path: Path) -> None:
    out_dir = tmp_path / "out-cdk"
    result = CliRunner().invoke(
        main,
        ["scan", str(SAMPLES / "cdk"), "-o", str(out_dir), "--scan-only"],
    )
    assert result.exit_code == 0, result.output
    report = out_dir / "scan-report.json"
    assert report.exists()
    data = json.loads(report.read_text())
    assert data["iac_type"] == "cdk"


@pytest.mark.smoke
def test_cli_scan_nonexistent_path_exits_nonzero(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path / "does-not-exist"), "--scan-only"],
    )
    assert result.exit_code != 0


@pytest.mark.smoke
def test_cli_scan_missing_api_keys_for_ai_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without --scan-only and without any provider env, the CLI should exit with a helpful error."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("IAC_PROVIDER", raising=False)
    # Set OLLAMA_HOST to a port that won't respond so auto-detect bypasses Ollama
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")
    out_dir = tmp_path / "out"
    result = CliRunner().invoke(
        main,
        ["scan", str(SAMPLES / "tf"), "-o", str(out_dir)],
    )
    assert result.exit_code != 0
    combined = (result.output + (str(result.exception) if result.exception else "")).lower()
    # Message should enumerate at least one remediation path
    assert "provider" in combined
    assert "--scan-only" in combined or "ollama" in combined or "openai" in combined
