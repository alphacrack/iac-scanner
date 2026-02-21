"""Terraform scanner - entry main.tf."""

from pathlib import Path

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
        """Terraform: main.tf and sibling .tf files."""
        if not self.entry_path.exists():
            return []
        files = [self.entry_path]
        for p in self.base_path.iterdir():
            if p.suffix == ".tf" and p != self.entry_path:
                files.append(p)
        return sorted(files)

    def scan(self) -> ScanResult:
        """Load main.tf (and related .tf) and produce scan result with placeholder findings."""
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
                raw_content += f"\n# --- {f.name} ---\n{f.read_text(encoding='utf-8', errors='replace')}"
            except Exception as e:
                raw_content += f"\n# --- {f.name} (read error: {e}) ---\n"
        return ScanResult(
            iac_type=self.iac_type,
            entry_path=self.entry_path,
            raw_content=raw_content.strip(),
            findings=[],
            metadata={"files": [str(p) for p in files]},
        )
