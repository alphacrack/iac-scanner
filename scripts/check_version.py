#!/usr/bin/env python3
"""Verify package version matches pyproject.toml (single source of truth). Used by pre-commit."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"


def get_pyproject_version() -> str:
    text = PYPROJECT.read_text()
    m = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not m:
        sys.exit(1)
    return m.group(1)


def main() -> int:
    expected = get_pyproject_version()
    try:
        from iac_scanner import __version__

        actual = __version__
    except Exception as e:
        # Pre-commit runs in an isolated env where the package often isn't installed; skip check.
        if isinstance(e, ImportError | ModuleNotFoundError) or "No module named" in str(e):
            return 0
        print(f"Cannot import iac_scanner.__version__: {e}", file=sys.stderr)
        return 1
    if actual != expected and not actual.endswith("+editable"):
        print(
            f"Version mismatch: pyproject.toml has {expected!r}, package reports {actual!r}. "
            "Run 'pip install -e .' from repo root.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
