"""Orchestrate scan -> structured analysis -> fix -> result, with caching.

Structured output means we no longer regex-strip code fences or json.loads()
a raw LLM string — the analysis task returns a Pydantic-validated FindingsList.

The cache layer (content-addressed SHA256) short-circuits repeat LLM calls
with identical inputs. See `iac_scanner.cache`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from iac_scanner.cache import CacheKey
from iac_scanner.cache import get as cache_get
from iac_scanner.cache import put as cache_put
from iac_scanner.cost import CostEstimate, enforce_budget, estimate
from iac_scanner.llm import make_llm
from iac_scanner.models import Finding, FindingsList
from iac_scanner.orchestration.tasks import PROMPT_VERSION, run_analysis, run_fix
from iac_scanner.scanners.base import IacScanner, ScanResult

if TYPE_CHECKING:
    from iac_scanner.llm.providers import LLMClient, Provider


@dataclass
class PipelineResult:
    """Result of the full pipeline: scan + findings + fixed code + metadata."""

    scan_result: ScanResult
    findings: list[Finding] = field(default_factory=list)
    findings_raw: str = "[]"
    fixed_code: str = ""
    prompt_version: str = PROMPT_VERSION
    provider: str | None = None
    analysis_model: str | None = None
    fix_model: str | None = None
    cache_hits: int = 0
    cost_estimates: list[CostEstimate] = field(default_factory=list)

    @property
    def projected_cost_usd(self) -> float:
        return sum(e.usd_est for e in self.cost_estimates)

    @property
    def findings_list(self) -> list[dict[str, object]]:
        """Back-compat accessor: findings as JSON-friendly dicts."""
        return [f.model_dump(exclude_none=True, mode="json") for f in self.findings]


def _serialize_findings(findings: FindingsList) -> str:
    """Dump FindingsList to a compact JSON string for the fix prompt and the report."""
    return json.dumps(
        [f.model_dump(exclude_none=True, mode="json") for f in findings.root],
        separators=(",", ":"),
    )


def _analysis_cache_key(raw_content: str, client: LLMClient) -> CacheKey:
    return CacheKey(
        call_kind="analysis",
        raw_content=raw_content,
        provider=client.provider,
        model=client.model,
        prompt_version=PROMPT_VERSION,
    )


def _fix_cache_key(raw_content: str, findings_json: str, client: LLMClient) -> CacheKey:
    return CacheKey(
        call_kind="fix",
        raw_content=raw_content,
        provider=client.provider,
        model=client.model,
        prompt_version=PROMPT_VERSION,
        extra=findings_json,
    )


def run_pipeline(
    scanner: IacScanner,
    *,
    provider: Provider | None = None,
    skip_fix: bool = False,
    analysis_client: LLMClient | None = None,
    fix_client: LLMClient | None = None,
) -> PipelineResult:
    """Orchestrate: scan -> structured analysis -> fix generation, with caching.

    `analysis_client` / `fix_client` are injection points for tests (mocked LLMClient).
    `provider` is honored only when the clients are not injected.
    """
    scan_result = scanner.scan()
    if not scan_result.raw_content:
        return PipelineResult(scan_result=scan_result)

    cache_hits = 0

    # Build clients up front so their (provider, model) is visible to the cache layer.
    if analysis_client is None:
        analysis_client = make_llm(provider=provider, role="analysis")
    if fix_client is None and not skip_fix:
        fix_client = make_llm(provider=provider, role="fix")

    # --- Pre-flight cost estimate + budget check ---
    # Estimate only the calls we haven't cached. Cache is checked lazily below; we
    # do a cheap cache-presence probe here so the budget check reflects actual spend.
    estimates: list[CostEstimate] = []
    if cache_get(_analysis_cache_key(scan_result.raw_content, analysis_client)) is None:
        estimates.append(
            estimate(
                scan_result.raw_content,
                provider=analysis_client.provider,
                model=analysis_client.model,
                call_kind="analysis",
            )
        )
    # Fix cost depends on findings_json, which we don't have yet. Estimate with raw_content
    # as a conservative upper bound for budget enforcement.
    if not skip_fix and fix_client is not None:
        estimates.append(
            estimate(
                scan_result.raw_content,
                provider=fix_client.provider,
                model=fix_client.model,
                call_kind="fix",
            )
        )
    enforce_budget(estimates)

    # --- Analysis: cache → LLM ---
    analysis_key = _analysis_cache_key(scan_result.raw_content, analysis_client)
    cached_analysis = cache_get(analysis_key)
    findings: FindingsList
    if cached_analysis is not None:
        try:
            findings = FindingsList.model_validate(cached_analysis)
            cache_hits += 1
        except Exception:  # noqa: BLE001
            findings = run_analysis(
                iac_type=scan_result.iac_type,
                entry_path=str(scan_result.entry_path),
                raw_content=scan_result.raw_content,
                client=analysis_client,
            )
            cache_put(analysis_key, findings.model_dump(exclude_none=True, mode="json"))
    else:
        findings = run_analysis(
            iac_type=scan_result.iac_type,
            entry_path=str(scan_result.entry_path),
            raw_content=scan_result.raw_content,
            client=analysis_client,
        )
        cache_put(analysis_key, findings.model_dump(exclude_none=True, mode="json"))

    findings_raw = _serialize_findings(findings)

    # --- Fix: cache → LLM ---
    fixed_code = ""
    if not skip_fix and findings.root and fix_client is not None:
        fix_key = _fix_cache_key(scan_result.raw_content, findings_raw, fix_client)
        cached_fix = cache_get(fix_key)
        if isinstance(cached_fix, str):
            fixed_code = cached_fix
            cache_hits += 1
        else:
            fixed_code = run_fix(
                iac_type=scan_result.iac_type,
                raw_content=scan_result.raw_content,
                findings_json=findings_raw,
                client=fix_client,
            )
            cache_put(fix_key, fixed_code)

    return PipelineResult(
        scan_result=scan_result,
        findings=list(findings.root),
        findings_raw=findings_raw,
        fixed_code=fixed_code,
        provider=analysis_client.provider,
        analysis_model=analysis_client.model,
        fix_model=fix_client.model if fix_client else None,
        cache_hits=cache_hits,
        cost_estimates=estimates,
    )
