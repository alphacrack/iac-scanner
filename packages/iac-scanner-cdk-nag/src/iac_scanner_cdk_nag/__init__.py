"""cdk-nag rule-engine adapter for iac-scanner.

Public API:
    run_cdk_nag(path, iac_type) -> list[Finding]
    cdk_nag_available() -> bool

Registered with iac-scanner core via the `iac_scanner.rule_engines` entry point
group — install this package and iac-scanner automatically discovers it.
"""

from iac_scanner_cdk_nag.adapter import (
    CdkNagError,
    CdkNagNotInstalled,
    cdk_nag_available,
    run_cdk_nag,
)

__version__ = "0.1.0"

__all__ = [
    "CdkNagError",
    "CdkNagNotInstalled",
    "__version__",
    "cdk_nag_available",
    "run_cdk_nag",
]
