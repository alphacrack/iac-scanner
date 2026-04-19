"""Pydantic models for findings, reports, and LLM structured output.

These schemas are the contract between:
  - The LLM (returns a validated FindingsList via structured output)
  - The rule engines (Checkov emits RuleFinding rows)
  - The report writer (JSON + SARIF outputs)

Keeping them in one module prevents drift across producers/consumers.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, RootModel


class Severity(str, Enum):
    """Finding severity. Keep aligned with SARIF 'level' mapping in output/sarif.py."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingSource(str, Enum):
    """Where a finding came from — used to dedupe and rank."""

    LLM = "llm"
    CHECKOV = "checkov"
    CDK_NAG = "cdk-nag"


class Finding(BaseModel):
    """A single security / compliance / best-practice finding.

    Produced by the LLM (with Pydantic structured output) or adapted from a rule engine.
    Matches the SARIF 'result' object roughly — we translate at emit time.
    """

    model_config = ConfigDict(extra="ignore")

    severity: Severity = Field(description="critical | high | medium | low | info")
    title: str = Field(description="Short human-readable title (<= 120 chars)")
    description: str = Field(description="What the issue is and why it matters")
    location: str = Field(description="File path and line / snippet reference, e.g. main.tf:12")
    source: FindingSource = Field(default=FindingSource.LLM)

    # Optional mappings — populated when known (Checkov always populates; LLM may).
    rule_id: str | None = Field(
        default=None,
        description="Stable identifier like CKV_AWS_20 (Checkov) or an LLM-assigned slug",
    )
    cwe: str | None = Field(default=None, description="CWE identifier, e.g. CWE-732")
    framework: str | None = Field(
        default=None,
        description="Compliance framework reference, e.g. 'CIS AWS 1.20', 'NIST-800-53 AC-3'",
    )
    remediation: str | None = Field(
        default=None,
        description="Short guidance for fixing the issue",
    )


class FindingsList(RootModel[list[Finding]]):
    """Structured-output wrapper. `llm.with_structured_output(FindingsList)` returns this.

    Use `.root` to get the underlying list. Empty list is valid — means 'no findings'.
    """

    root: list[Finding]


class LLMAugmentedFindings(BaseModel):
    """Output shape for the hybrid-mode analysis step.

    The LLM receives rule-engine findings as context and returns:
      - additional_findings: issues the rule engine missed (architectural, cross-resource)
      - false_positive_flags: rule findings that are FP in this codebase's context
    """

    model_config = ConfigDict(extra="ignore")

    additional_findings: list[Finding] = Field(default_factory=list)
    false_positive_flags: list[str] = Field(
        default_factory=list,
        description="Rule IDs (e.g. CKV_AWS_20) the LLM believes are false positives in context",
    )


class VerificationResult(BaseModel):
    """Result of re-running the rule engine on LLM-generated fixed code."""

    model_config = ConfigDict(extra="ignore")

    status: str = Field(description="'PASS' or 'FAIL'")
    findings_before: int = 0
    findings_after: int = 0
    new_high_findings: int = 0
    new_critical_findings: int = 0
    details: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    """Top-level report written to scan-report.json.

    The same data model is the input to the SARIF emitter and the JSON writer.
    """

    model_config = ConfigDict(extra="ignore")

    iac_type: str
    entry_path: str
    findings: list[Finding] = Field(default_factory=list)
    findings_raw: str | None = Field(
        default=None,
        description="Raw LLM response string (pre-parse), kept for debugging",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
    verification: VerificationResult | None = None
    iac_scanner_version: str | None = None
    prompt_version: str | None = None
    provider: str | None = Field(default=None, description="LLM provider used: openai|anthropic|github|ollama|none")
    model: str | None = None
