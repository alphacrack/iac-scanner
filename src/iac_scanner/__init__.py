"""IaC Scanner - CLI to scan and fix Terraform and CDK with LangChain-orchestrated agents.

The package version comes from git tags via setuptools-scm. At build time
setuptools-scm writes `_version.py`; in installed environments we fall back to
`importlib.metadata`. Neither path requires editing `pyproject.toml`.
"""

from __future__ import annotations


def _get_version() -> str:
    # Preferred: file written by setuptools-scm at build time (works in editable
    # installs and from sdists that include it). The `unused-ignore` code keeps
    # mypy --strict happy in both states: when _version.py exists (after install,
    # which is what CI sees) the ignore is unused and would otherwise error; when
    # it doesn't exist (fresh checkout) the import-not-found needs to be ignored.
    try:
        from ._version import __version__ as _scm_version  # type: ignore[import-not-found,unused-ignore]

        return str(_scm_version)
    except ImportError:
        pass

    # Fallback: metadata of the installed distribution.
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("iac-scanner")
        except PackageNotFoundError:
            pass
    except ImportError:
        pass

    # Last resort: clearly-fake version so logs/reports never crash.
    return "0.0.0+unknown"


__version__ = _get_version()
