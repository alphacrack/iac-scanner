"""SARIF 2.1.0 emitter.

SARIF is the format GitHub Code Scanning, GitLab Security Dashboard, SonarQube,
and most enterprise SAST pipelines ingest. Emitting SARIF unlocks the "optional CI
integration" surface of the product (see the v1 release plan).

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
Schema URL embedded in output is the canonical one that validators expect.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from iac_scanner.models import Finding, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "iac-scanner"
TOOL_INFO_URI = "https://github.com/bishwasjha/iac-scanner"

# SARIF 'level' has: none | note | warning | error. Map our 5 severities.
_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

# SARIF 'security-severity' (0.0-10.0) — maps to GitHub Code Scanning severity filter.
_SEVERITY_TO_SCORE: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}

# Location strings come in many shapes from the LLM. Best-effort parse:
#   "main.tf:12"
#   "main.tf:12-15"
#   "main.tf line 12"
#   "src/infra/main.tf:12:4"
#   "main.tf"                  (no line)
#   "resource aws_s3_bucket.x" (no file — skipped)
_LOCATION_RE = re.compile(
    r"""^
    (?P<file>[^\s:]+\.(?:tf|ts|js|tsx|jsx|yaml|yml|json|hcl|py))  # a plausible file name
    (?:[:\s]+(?:line\s+)?(?P<line>\d+))?                           # optional start line
    (?:\s*[-–]\s*(?P<endline>\d+))?                                # optional end line
    (?::(?P<col>\d+))?                                             # optional column
    \s*$""",
    re.VERBOSE,
)


def _parse_location(raw: str) -> tuple[str | None, int | None, int | None, int | None]:
    """Best-effort: return (file, start_line, end_line, start_col). Any may be None."""
    if not raw:
        return None, None, None, None
    m = _LOCATION_RE.match(raw.strip())
    if not m:
        return None, None, None, None
    file_ = m.group("file")
    line = int(m.group("line")) if m.group("line") else None
    endline = int(m.group("endline")) if m.group("endline") else None
    col = int(m.group("col")) if m.group("col") else None
    return file_, line, endline, col


def _rule_id(finding: Finding, default_idx: int) -> str:
    """Prefer explicit rule_id; fall back to a stable slug from the title."""
    if finding.rule_id:
        return finding.rule_id
    slug = re.sub(r"[^a-z0-9]+", "-", finding.title.lower()).strip("-")[:60] or f"iac-{default_idx}"
    return f"IAC-{slug}"


def build_sarif(
    findings: list[Finding],
    *,
    tool_version: str,
    entry_path: str,
    iac_type: str,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from findings. Returns a JSON-serializable dict."""
    # Deduplicate rules: one SARIF rule per unique rule_id/title pair.
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}

    results: list[dict[str, Any]] = []
    for idx, f in enumerate(findings):
        rid = _rule_id(f, idx)
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rule_entry: dict[str, Any] = {
                "id": rid,
                "name": f.title[:60],
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL[f.severity]},
                "properties": {
                    "tags": _rule_tags(f),
                    "security-severity": _SEVERITY_TO_SCORE[f.severity],
                    "source": f.source.value,
                },
            }
            if f.remediation:
                rule_entry["help"] = {"text": f.remediation}
            if f.cwe:
                rule_entry["properties"]["cwe"] = f.cwe
            if f.framework:
                rule_entry["properties"]["framework"] = f.framework
            rules.append(rule_entry)

        file_, line, endline, col = _parse_location(f.location)
        # Fall back to entry file if parsing failed so the finding still has a location.
        uri = file_ or Path(entry_path).name
        region: dict[str, Any] = {}
        if line is not None:
            region["startLine"] = line
        if endline is not None:
            region["endLine"] = endline
        if col is not None:
            region["startColumn"] = col

        physical_location: dict[str, Any] = {
            "artifactLocation": {"uri": uri},
        }
        if region:
            physical_location["region"] = region

        result_entry: dict[str, Any] = {
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": _SEVERITY_TO_LEVEL[f.severity],
            "message": {"text": f.description},
            "locations": [{"physicalLocation": physical_location}],
        }
        # Keep the raw location text for users whose viewer shows properties.
        result_entry["properties"] = {
            "source": f.source.value,
            "raw_location": f.location,
        }
        results.append(result_entry)

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": tool_version,
                        "informationUri": TOOL_INFO_URI,
                        "rules": rules,
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "properties": {"iac_type": iac_type, "entry_path": entry_path},
                "results": results,
            }
        ],
    }
    return sarif


def _rule_tags(f: Finding) -> list[str]:
    tags: list[str] = ["security", "iac"]
    if f.source.value:
        tags.append(f"source:{f.source.value}")
    if f.framework:
        tags.append(f"framework:{f.framework}")
    return tags


def write_sarif(
    findings: list[Finding],
    output_path: Path,
    *,
    tool_version: str,
    entry_path: str,
    iac_type: str,
) -> Path:
    """Serialize SARIF JSON to `output_path`. Returns the path written."""
    sarif = build_sarif(
        findings,
        tool_version=tool_version,
        entry_path=entry_path,
        iac_type=iac_type,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return output_path
