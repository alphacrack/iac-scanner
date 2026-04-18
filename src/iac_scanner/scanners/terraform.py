"""Terraform scanner - entry main.tf."""

from __future__ import annotations

from pathlib import Path

from iac_scanner.scanners._filters import (
    enforce_input_size,
    redact_secrets,
    should_skip,
)
from iac_scanner.scanners.base import IacScanner, ScanResult


class TerraformScanner(IacScanner):
    """Scanner for Terraform projects with entry main.tf."""

    iac_type = "terraform"
    entry_name = "main.tf"

    def __init__(self, base_path: Path):
        super().__init__(base_path)
        if self.base_path.is_file() and self.base_path.name == self.entry_name:
            self.base_path = self.base_path.parent
            self.entry_path = self.base_path / self.entry_name

    def list_files(self) -> list[Path]:
        """Terraform: main.tf and sibling .tf files, minus skip-list matches."""
        if not self.entry_path.exists():
            return []
        files = [self.entry_path]
        for p in self.base_path.iterdir():
            if p.suffix == ".tf" and p != self.entry_path and not should_skip(p):
                files.append(p)
        return sorted(files)

    def scan(self) -> ScanResult:
        """Load main.tf (and related .tf), redact secrets, enforce size cap."""
        files = self.list_files()
        if not files:
            return ScanResult(
                iac_type=self.iac_type,
                entry_path=self.entry_path,
                raw_content="",
                findings=[{"error": "No main.tf or .tf files found"}],
            )
        raw_content = ""
        for f in files:
            try:
                file_text = f.read_text(encoding="utf-8", errors="replace")
                raw_content += f"\n# --- {f.name} ---\n{file_text}"
            except Exception as e:  # noqa: BLE001
                raw_content += f"\n# --- {f.name} (read error: {e}) ---\n"

        raw_content = redact_secrets(raw_content.strip())
        enforce_input_size(raw_content)

        return ScanResult(
            iac_type=self.iac_type,
            entry_path=self.entry_path,
            raw_content=raw_content,
            findings=[],
            metadata={"files": [str(p) for p in files]},
        )
