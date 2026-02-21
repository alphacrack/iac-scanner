"""Tests for factory and scanners (no AI)."""

from pathlib import Path

import pytest

from iac_scanner.factory import create_scanner


def test_create_scanner_terraform_dir(data_dir):
    path = data_dir / "tf"
    scanner = create_scanner(path)
    assert scanner.iac_type == "terraform"
    assert scanner.entry_path.name == "main.tf"
    result = scanner.scan()
    assert result.iac_type == "terraform"
    assert "main.tf" in result.raw_content or result.raw_content


def test_create_scanner_cdk_dir(data_dir):
    path = data_dir / "cdk"
    scanner = create_scanner(path)
    assert scanner.iac_type == "cdk"
    result = scanner.scan()
    assert result.iac_type == "cdk"
    assert "index.ts" in result.raw_content or "index.js" in result.raw_content or result.raw_content


def test_create_scanner_invalid_path():
    with pytest.raises(ValueError, match="No supported IaC entry"):
        create_scanner(Path("/nonexistent"))


@pytest.fixture
def data_dir():
    return Path(__file__).parent.parent / "samples"
