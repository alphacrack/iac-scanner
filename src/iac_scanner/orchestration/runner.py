"""Orchestrate scan -> analysis (AI 1) -> fix (AI 2) -> output."""

import json
import re
from typing import Any

from iac_scanner.orchestration.tasks import run_analysis, run_fix
from iac_scanner.scanners.base import IacScanner, ScanResult


def _extract_json_array(raw: str) -> str:
    """Strip markdown code fences (e.g. ```json ... ```) so the string is parseable JSON."""
    text = raw.strip()
    # Match optional opening ```json or ```
    match = re.match(r"^```(?:json)?\s*\n?(.*)\n?```\s*$", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text


class PipelineResult:
    """Result of the full pipeline: report + fixed code."""

    def __init__(
        self,
        scan_result: ScanResult,
        findings_raw: str,
        fixed_code: str,
    ):
        self.scan_result = scan_result
        self.findings_raw = findings_raw
        self.fixed_code = fixed_code

    @property
    def findings_list(self) -> list[dict[str, Any]]:
        """Parsed findings (JSON array). Strips markdown code fences if present."""
        try:
            return json.loads(_extract_json_array(self.findings_raw))
        except (json.JSONDecodeError, TypeError):
            return []


def run_pipeline(scanner: IacScanner) -> PipelineResult:
    """
    Orchestrate: scan -> analyze (analysis AI) -> generate fix (fix AI).
    Each task uses a different AI as configured in tasks.py.
    """
    scan_result = scanner.scan()
    if not scan_result.raw_content:
        return PipelineResult(
            scan_result=scan_result,
            findings_raw="[]",
            fixed_code="",
        )
    findings_raw = run_analysis(
        iac_type=scan_result.iac_type,
        entry_path=str(scan_result.entry_path),
        raw_content=scan_result.raw_content,
    )
    fixed_code = run_fix(
        iac_type=scan_result.iac_type,
        raw_content=scan_result.raw_content,
        findings=findings_raw,
    )
    return PipelineResult(
        scan_result=scan_result,
        findings_raw=findings_raw,
        fixed_code=fixed_code,
    )
