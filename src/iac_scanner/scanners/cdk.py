"""CDK scanner - entry index.ts (or index.js)."""

from pathlib import Path

from iac_scanner.scanners.base import IacScanner, ScanResult


class CdkScanner(IacScanner):
    """Scanner for AWS CDK projects with entry index.ts or index.js."""

    iac_type = "cdk"
    entry_name = "index.ts"

    def __init__(self, base_path: Path):
        super().__init__(base_path)
        if self.base_path.is_file() and self.base_path.name in ("index.ts", "index.js"):
            self.base_path = self.base_path.parent
        self._entry_resolved = self._resolve_entry()
        self.entry_path = self._entry_resolved

    def _resolve_entry(self) -> Path:
        """Resolve entry to index.ts or index.js."""
        for name in ("index.ts", "index.js"):
            p = self.base_path / name
            if p.exists():
                return p
        if self.base_path.is_file():
            p = Path(self.base_path)
            if p.name in ("index.ts", "index.js"):
                return p
        return self.base_path / "index.ts"

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        path = Path(path).resolve()
        if path.is_file():
            return path.name in ("index.ts", "index.js")
        return (path / "index.ts").is_file() or (path / "index.js").is_file()

    def list_files(self) -> list[Path]:
        """CDK: entry file and common lib/stack files in same dir."""
        if not self._entry_resolved.exists():
            return []
        files = [self._entry_resolved]
        base = self._entry_resolved.parent
        for name in ("lib", "bin"):
            d = base / name
            if d.is_dir():
                for ext in (".ts", ".js"):
                    files.extend(d.glob(f"*{ext}"))
        return sorted(set(files))

    def scan(self) -> ScanResult:
        """Load CDK entry and related files."""
        files = self.list_files()
        if not files:
            return ScanResult(
                iac_type=self.iac_type,
                entry_path=self._entry_resolved,
                raw_content="",
                findings=[{"error": "No index.ts/index.js or related files found"}],
            )
        raw_content = ""
        for f in files:
            try:
                raw_content += f"\n// --- {f.name} ---\n{f.read_text(encoding='utf-8', errors='replace')}"
            except Exception as e:
                raw_content += f"\n// --- {f.name} (read error: {e}) ---\n"
        return ScanResult(
            iac_type=self.iac_type,
            entry_path=self._entry_resolved,
            raw_content=raw_content.strip(),
            findings=[],
            metadata={"files": [str(p) for p in files]},
        )
