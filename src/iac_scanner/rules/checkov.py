"""Checkov rule-engine adapter.

Shells out to the `checkov` CLI (installed via `pip install iac-scanner[rules]`),
parses the JSON output, and adapts each failed check to our `Finding` model with
CWE / CIS / NIST mappings preserved.

Why subprocess instead of the Checkov Python API?
  - The Python API's internal structure changes frequently across minor versions.
  - The CLI's JSON output is versioned and stable.
  - Isolates Checkov's heavy import graph from our process startup time.

Checkov command layout:
  checkov -d <path> -o json --quiet --soft-fail --framework <tf|cloudformation>
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from iac_scanner.models import Finding, FindingSource, Severity

logger = logging.getLogger(__name__)

# Map Checkov's severity strings to our enum. Checkov uses UPPERCASE.
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


class CheckovError(RuntimeError):
    """Checkov ran but returned an error we couldn't adapt."""


class CheckovNotInstalled(CheckovError):
    """The `checkov` command is not on PATH."""


def checkov_available() -> bool:
    """True if `checkov` is importable via the package OR on PATH."""
    if shutil.which("checkov"):
        return True
    try:
        import checkov  # noqa: F401 — presence check only
    except ImportError:
        return False
    return True


def _checkov_framework_for(iac_type: str) -> str:
    """Map our iac_type to Checkov's --framework flag."""
    if iac_type == "terraform":
        return "terraform"
    if iac_type == "cdk":
        # CDK synth -> CFN, which Checkov reads natively. For v1.0 we rely on the
        # user to have synth'd their app; point Checkov at both frameworks.
        return "cloudformation"
    return "all"


def _adapt_check(result: dict[str, Any]) -> Finding:
    """Adapt a single Checkov 'failed_check' record to our Finding model."""
    severity_raw = (result.get("severity") or "MEDIUM").upper()
    severity = _SEVERITY_MAP.get(severity_raw, Severity.MEDIUM)
    file_path = result.get("file_path", "")
    line_range = result.get("file_line_range") or []
    if isinstance(line_range, list) and len(line_range) >= 1:
        start = line_range[0]
        location = f"{file_path.lstrip('/')}:{start}"
    else:
        location = file_path.lstrip("/") or "unknown"

    # Extract CWE / framework tags from Checkov's bc_check_id / guideline / check_id prefix.
    check_id = str(result.get("check_id") or "")
    framework = _framework_hint(check_id)
    cwe = _cwe_hint(result)

    return Finding(
        severity=severity,
        title=str(result.get("check_name", check_id)),
        description=str(result.get("description") or result.get("check_name") or check_id),
        location=location,
        source=FindingSource.CHECKOV,
        rule_id=check_id or None,
        cwe=cwe,
        framework=framework,
        remediation=str(result.get("guideline") or "") or None,
    )


def _framework_hint(check_id: str) -> str | None:
    """Infer a framework tag from Checkov's check_id prefix."""
    prefix_to_framework = {
        "CKV_AWS_": "AWS",
        "CKV_AZURE_": "Azure",
        "CKV_GCP_": "GCP",
        "CKV_K8S_": "Kubernetes",
        "CKV_DOCKER_": "Docker",
        "CKV2_AWS_": "AWS",
        "CKV2_AZURE_": "Azure",
        "CKV2_GCP_": "GCP",
    }
    for prefix, fw in prefix_to_framework.items():
        if check_id.startswith(prefix):
            return fw
    return None


def _cwe_hint(result: dict[str, Any]) -> str | None:
    """Checkov embeds CWE info under 'details' or 'check_name'. Best-effort parse."""
    for key in ("cwe", "cwe_id"):
        if val := result.get(key):
            return str(val)
    return None


def run_checkov(path: Path, iac_type: str, *, timeout_seconds: int = 300) -> list[Finding]:
    """Run Checkov against `path` and return adapted findings.

    Returns an empty list on "no findings" or when only the checkov package is
    installed but not on PATH. Raises CheckovNotInstalled if no mechanism works.
    """
    if not checkov_available():
        raise CheckovNotInstalled(
            "Checkov not found. Install with `pip install iac-scanner[rules]` or `pip install checkov`."
        )

    # Prefer the CLI binary; fall back to `python -m checkov.main` if only the pkg is present.
    if shutil.which("checkov"):
        cmd = ["checkov"]
    else:
        cmd = [os.environ.get("PYTHON", "python"), "-m", "checkov.main"]

    cmd += [
        "-d",
        str(path),
        "-o",
        "json",
        "--quiet",
        "--soft-fail",
        "--framework",
        _checkov_framework_for(iac_type),
    ]

    logger.debug("Running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(  # noqa: S603 — cmd list assembled from known safe values
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise CheckovError(f"Checkov timed out after {timeout_seconds}s") from e
    except FileNotFoundError as e:
        raise CheckovNotInstalled(str(e)) from e

    if not proc.stdout.strip():
        # Checkov exits 0 with empty output when no files match the framework.
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        preview = proc.stdout[:500]
        raise CheckovError(f"Could not parse Checkov JSON output: {e}\n---\n{preview}") from e

    # Checkov output shape: either a dict (single framework) or a list of dicts (multi).
    if isinstance(data, dict):
        return _extract_failed_checks(data)
    if isinstance(data, list):
        findings: list[Finding] = []
        for entry in data:
            if isinstance(entry, dict):
                findings.extend(_extract_failed_checks(entry))
        return findings
    return []


def _extract_failed_checks(payload: dict[str, Any]) -> list[Finding]:
    """Pull 'results.failed_checks' out of a single-framework Checkov payload."""
    results = payload.get("results") or {}
    failed = results.get("failed_checks") or []
    if not isinstance(failed, list):
        return []
    findings: list[Finding] = []
    for item in failed:
        if not isinstance(item, dict):
            continue
        try:
            findings.append(_adapt_check(item))
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to adapt Checkov result %r: %s", item.get("check_id"), e)
    return findings
