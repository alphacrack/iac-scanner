"""cdk-nag adapter: `cdk synth` → parse nag annotations → iac-scanner Findings.

Design notes:
- We shell out to `cdk synth` rather than import cdk-nag as a Python library
  because cdk-nag is a Node/TS package. The cost is one subprocess; the benefit
  is zero runtime coupling to Node.
- cdk-nag emits annotations on stderr in a stable format:
    [Error at /MyStack/MyBucket/Resource] AwsSolutions-S1: ...message...
- We parse those lines into Finding objects. Warnings are mapped to MEDIUM,
  errors to HIGH by default (some nag rules escalate to CRITICAL — we map
  specific packs where documented).
- If the user's CDK app doesn't have nag aspects wired, stderr carries no
  annotations and we return an empty list — NOT an error. The LLM path still
  runs upstream.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from iac_scanner.models import Finding, FindingSource, Severity

logger = logging.getLogger(__name__)

# Nag annotation patterns. The `at` path is the CDK construct path; we map it
# to a plausible file location the scanner's caller may recognize.
#   [Error at /<stack>/.../Resource] <RuleId>: <message>
#   [Warning at /<stack>/.../Resource] <RuleId>: <message>
_NAG_ANNOTATION_RE = re.compile(
    r"""
    ^\[
    (?P<level>Error|Warning)
    \s+at\s+
    (?P<construct_path>[^\]]+)
    \]\s+
    # Rule IDs can contain letters, digits, underscores, dashes, and dots
    # (e.g. AwsSolutions-S1, HIPAA.Security-S3Encryption, NIST800-53.R5-IAMPolicy,
    # PCI.DSS.321-CheckName).
    (?P<rule_id>[A-Za-z][\w.\-]+)
    :\s*
    (?P<message>.+)
    $
    """,
    re.VERBOSE,
)

# cdk-nag rule packs → framework + severity mapping.
#   AwsSolutions-*  → AWS Well-Architected (HIGH default, escalate SEC → CRITICAL)
#   HIPAA.Security-* → HIPAA Security Rule (HIGH)
#   NIST800-53.R5-* → NIST 800-53 rev 5 (HIGH)
#   PCI.DSS.321-*   → PCI-DSS 3.2.1 (HIGH)
_FRAMEWORK_PREFIXES: tuple[tuple[str, str], ...] = (
    ("AwsSolutions-", "AWS Well-Architected"),
    ("HIPAA.Security-", "HIPAA Security Rule"),
    ("NIST800-53.R5-", "NIST 800-53 rev 5"),
    ("NIST800-53.R4-", "NIST 800-53 rev 4"),
    ("PCI.DSS.321-", "PCI-DSS 3.2.1"),
    ("FedRAMP-", "FedRAMP"),
)


class CdkNagError(RuntimeError):
    """cdk-nag ran but we couldn't interpret the output."""


class CdkNagNotInstalled(CdkNagError):
    """The `cdk` CLI isn't on PATH."""


def cdk_nag_available() -> bool:
    """True when the CDK CLI is reachable. We don't check for cdk-nag itself —
    the user's CDK app must have aspects wired; if not, we return zero findings.
    """
    return shutil.which("cdk") is not None


def _severity_for(rule_id: str, level: str) -> Severity:
    """Map (rule_id, annotation level) → iac-scanner Severity.

    Heuristic: 'Error'-level nag annotations are HIGH. Rules explicitly flagged
    as critical (IAM5 wildcard, S1 encryption-at-rest, KMS2 no-rotation) map
    to CRITICAL. Warnings map to MEDIUM.
    """
    if level == "Warning":
        return Severity.MEDIUM
    critical_rules = {
        "AwsSolutions-IAM5",  # IAM policies with wildcards
        "AwsSolutions-S1",  # S3 server-side encryption
        "AwsSolutions-KMS2",  # KMS key rotation
        "AwsSolutions-APIG2",  # API GW request validation
        "HIPAA.Security-S3BucketLoggingEnabled",
    }
    if rule_id in critical_rules:
        return Severity.CRITICAL
    return Severity.HIGH


def _framework_for(rule_id: str) -> str | None:
    for prefix, framework in _FRAMEWORK_PREFIXES:
        if rule_id.startswith(prefix):
            return framework
    return None


def _construct_path_to_location(construct_path: str) -> str:
    """cdk-nag reports the CDK construct path (e.g. /MyStack/MyBucket/Resource).
    Convert to a best-effort file location for the report. Since cdk-nag
    operates on the synthesized graph, we can't recover an exact file:line —
    we surface the construct path verbatim under an `index.ts` anchor so SARIF
    viewers at least show a grouped location.
    """
    cleaned = construct_path.strip().lstrip("/")
    return f"index.ts:{cleaned}"


def _parse_annotations(stderr: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _NAG_ANNOTATION_RE.match(line)
        if not m:
            continue
        rule_id = m.group("rule_id")
        level = m.group("level")
        message = m.group("message").strip()
        findings.append(
            Finding(
                severity=_severity_for(rule_id, level),
                title=f"{rule_id}: {message[:100]}",
                description=message,
                location=_construct_path_to_location(m.group("construct_path")),
                source=FindingSource.CDK_NAG,
                rule_id=rule_id,
                framework=_framework_for(rule_id),
                remediation=None,  # cdk-nag's message is the remediation
            )
        )
    return findings


def run_cdk_nag(
    path: Path,
    iac_type: str,
    *,
    timeout_seconds: int = 600,
) -> list[Finding]:
    """Run `cdk synth` in `path` and return findings parsed from nag annotations.

    Contract (matches core's rule-engine interface so entry_points can resolve it):
        - path: project directory
        - iac_type: 'terraform' | 'cdk' — cdk-nag only runs on CDK; returns []
          for other types so the dispatcher can fan out cheaply
        - returns: list[Finding], possibly empty

    Raises CdkNagNotInstalled if the `cdk` CLI is missing.
    """
    if iac_type != "cdk":
        return []

    if not cdk_nag_available():
        raise CdkNagNotInstalled(
            "`cdk` not found on PATH. Install the AWS CDK Toolkit "
            "(`npm i -g aws-cdk`) and wire cdk-nag aspects in your app to use "
            "this rule engine."
        )

    # --quiet suppresses the template output; nag annotations still go to stderr.
    # --ci makes cdk avoid interactive prompts.
    cmd = ["cdk", "synth", "--quiet", "--ci"]
    logger.debug("Running: %s in %s", " ".join(cmd), path)
    try:
        proc = subprocess.run(  # noqa: S603 — cmd from hardcoded tokens
            cmd,
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise CdkNagError(f"cdk synth timed out after {timeout_seconds}s") from e
    except FileNotFoundError as e:
        raise CdkNagNotInstalled(str(e)) from e

    # cdk-nag "Error" annotations cause synth to exit non-zero. That's not a
    # failure for us — we still want the annotations. Only surface a genuine
    # synth crash (non-nag) as an error.
    findings = _parse_annotations(proc.stderr)
    if proc.returncode != 0 and not findings:
        # No annotations parsed but cdk synth failed — the user's CDK app has
        # a genuine issue (missing deps, TypeScript compile error, etc).
        preview = (proc.stderr or proc.stdout)[:500]
        raise CdkNagError(f"cdk synth failed (exit {proc.returncode}):\n{preview}")

    return findings
