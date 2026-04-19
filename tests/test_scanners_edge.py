"""Edge-case tests for scanners/terraform.py, scanners/cdk.py, and factory.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from iac_scanner.factory import create_scanner
from iac_scanner.scanners.cdk import CdkScanner
from iac_scanner.scanners.terraform import TerraformScanner


class TestFactoryBranches:
    def test_returns_terraform_for_main_tf_file(self, tmp_path: Path) -> None:
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        scanner = create_scanner(tmp_path / "main.tf")
        assert scanner.iac_type == "terraform"

    def test_returns_cdk_for_index_ts_file(self, tmp_path: Path) -> None:
        (tmp_path / "index.ts").write_text("// cdk app")
        scanner = create_scanner(tmp_path / "index.ts")
        assert scanner.iac_type == "cdk"

    def test_returns_cdk_for_index_js_file(self, tmp_path: Path) -> None:
        (tmp_path / "index.js").write_text("// cdk app")
        scanner = create_scanner(tmp_path / "index.js")
        assert scanner.iac_type == "cdk"

    def test_unsupported_file_raises(self, tmp_path: Path) -> None:
        (tmp_path / "stack.py").write_text("")
        with pytest.raises(ValueError, match="No supported IaC entry"):
            create_scanner(tmp_path / "stack.py")

    def test_directory_without_entry_raises(self, tmp_path: Path) -> None:
        (tmp_path / "readme.md").write_text("")
        with pytest.raises(ValueError, match="No supported IaC entry"):
            create_scanner(tmp_path)


class TestTerraformScannerEdges:
    def test_scans_single_main_tf(self, tmp_path: Path) -> None:
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        scanner = TerraformScanner(tmp_path)
        r = scanner.scan()
        assert r.iac_type == "terraform"
        assert "aws_s3_bucket" in r.raw_content
        assert r.metadata["files"]

    def test_scans_multiple_tf_files(self, tmp_path: Path) -> None:
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        (tmp_path / "variables.tf").write_text('variable "region" {}')
        (tmp_path / "outputs.tf").write_text('output "bucket_id" { value = aws_s3_bucket.b.id }')
        r = TerraformScanner(tmp_path).scan()
        assert "aws_s3_bucket" in r.raw_content
        assert "variable" in r.raw_content
        assert "output" in r.raw_content

    def test_skips_tfstate_and_tfvars(self, tmp_path: Path) -> None:
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        (tmp_path / "terraform.tfstate").write_text('{"version": 4, "secret": "DANGER"}')
        (tmp_path / "prod.tfvars").write_text('secret_key = "leaked"')
        r = TerraformScanner(tmp_path).scan()
        # Skipped files must not appear in raw_content nor metadata
        assert "DANGER" not in r.raw_content
        assert "leaked" not in r.raw_content
        file_names = [Path(p).name for p in r.metadata["files"]]
        assert "terraform.tfstate" not in file_names
        assert "prod.tfvars" not in file_names

    def test_redacts_secret_in_tf_source(self, tmp_path: Path) -> None:
        (tmp_path / "main.tf").write_text('provider "aws" {\n  access_key = "AKIAIOSFODNN7EXAMPLE"\n}\n')
        r = TerraformScanner(tmp_path).scan()
        assert "AKIAIOSFODNN7EXAMPLE" not in r.raw_content
        assert "REDACTED_SECRET" in r.raw_content

    def test_missing_entry_returns_error_finding(self, tmp_path: Path) -> None:
        # No main.tf present; scanner .scan() returns an error finding
        scanner = TerraformScanner(tmp_path)
        r = scanner.scan()
        assert r.raw_content == ""
        assert r.findings and "No main.tf" in r.findings[0]["error"]

    def test_can_handle_file_path(self, tmp_path: Path) -> None:
        entry = tmp_path / "main.tf"
        entry.write_text("# tf")
        assert TerraformScanner.can_handle(entry)
        # Directory with main.tf also handleable
        assert TerraformScanner.can_handle(tmp_path)


class TestCdkScannerEdges:
    def test_scans_index_ts_only(self, tmp_path: Path) -> None:
        (tmp_path / "index.ts").write_text("// root")
        r = CdkScanner(tmp_path).scan()
        assert r.iac_type == "cdk"
        assert "// root" in r.raw_content

    def test_resolves_index_js_when_no_ts(self, tmp_path: Path) -> None:
        (tmp_path / "index.js").write_text("// cdk in js")
        r = CdkScanner(tmp_path).scan()
        assert "cdk in js" in r.raw_content

    def test_scans_lib_and_bin_subdirs(self, tmp_path: Path) -> None:
        (tmp_path / "index.ts").write_text("// root")
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "stack.ts").write_text("// stack")
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin" / "app.ts").write_text("// app")
        r = CdkScanner(tmp_path).scan()
        assert "// stack" in r.raw_content
        assert "// app" in r.raw_content

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        (tmp_path / "index.ts").write_text("// root")
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "stack.ts").write_text("// stack")
        (tmp_path / "lib" / "node_modules").mkdir()
        (tmp_path / "lib" / "node_modules" / "evil.ts").write_text("// malicious payload")
        r = CdkScanner(tmp_path).scan()
        assert "malicious payload" not in r.raw_content

    def test_missing_entry_returns_error_finding(self, tmp_path: Path) -> None:
        r = CdkScanner(tmp_path).scan()
        assert r.raw_content == ""
        assert r.findings and "index.ts" in r.findings[0]["error"]

    def test_can_handle_file_and_directory(self, tmp_path: Path) -> None:
        entry = tmp_path / "index.ts"
        entry.write_text("// c")
        assert CdkScanner.can_handle(entry)
        assert CdkScanner.can_handle(tmp_path)

    def test_can_handle_rejects_unknown_files(self, tmp_path: Path) -> None:
        entry = tmp_path / "app.py"
        entry.write_text("")
        assert CdkScanner.can_handle(entry) is False

    def test_accepts_index_ts_as_entry_file_directly(self, tmp_path: Path) -> None:
        entry = tmp_path / "index.ts"
        entry.write_text("// content")
        scanner = CdkScanner(entry)
        assert scanner.base_path == tmp_path
        assert scanner.entry_path == entry
