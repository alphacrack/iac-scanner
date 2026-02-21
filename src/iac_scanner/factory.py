"""Factory to create the appropriate IaC scanner from path (main.tf vs index.ts)."""

from pathlib import Path

from iac_scanner.scanners.base import IacScanner
from iac_scanner.scanners.cdk import CdkScanner
from iac_scanner.scanners.terraform import TerraformScanner


def create_scanner(path: str | Path) -> IacScanner:
    """
    Create the correct scanner for the given path.
    - If path contains main.tf (file or directory with main.tf) -> TerraformScanner
    - If path contains index.ts or index.js -> CdkScanner
    Raises ValueError if neither is detected.
    """
    path = Path(path).resolve()
    if path.is_file():
        if TerraformScanner.can_handle(path):
            return TerraformScanner(path)
        if CdkScanner.can_handle(path):
            return CdkScanner(path)
    else:
        if TerraformScanner.can_handle(path):
            return TerraformScanner(path)
        if CdkScanner.can_handle(path):
            return CdkScanner(path)
    raise ValueError(
        f"No supported IaC entry found at {path}. "
        "Expected directory or file: main.tf (Terraform) or index.ts/index.js (CDK)."
    )
