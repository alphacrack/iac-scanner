"""Abstract base for IaC scanners (Factory pattern)."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class ScanResult(BaseModel):
    """Result of scanning IaC code."""

    iac_type: str
    entry_path: Path
    raw_content: str
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}


class IacScanner(ABC):
    """Abstract scanner for Infrastructure-as-Code. Concrete scanners (TF, CDK) implement this."""

    iac_type: str = "base"
    entry_name: str = ""

    def __init__(self, base_path: Path):
        self.base_path = Path(base_path).resolve()
        self.entry_path = self.base_path / self.entry_name

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Return True if this scanner can handle the given path (e.g. main.tf or index.ts)."""
        path = Path(path).resolve()
        if path.is_file():
            return path.name == cls.entry_name
        return (path / cls.entry_name).is_file()

    @abstractmethod
    def scan(self) -> ScanResult:
        """Load and scan the IaC code; return findings and content."""
        ...

    @abstractmethod
    def list_files(self) -> list[Path]:
        """Return list of relevant IaC files to include in context."""
        ...
