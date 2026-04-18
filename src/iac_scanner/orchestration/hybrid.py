"""Hybrid pipeline: rule-engine pre-pass + LLM augment + fix.

Post-fix verification (re-running the rule engine on the fixed code) is tracked
as a v1.1 item — requires a temp-dir dance that's cleaner with an `--apply` flow.
For v1.0 we stop at the merged findings + fix.

Flow:
    scan -> rule engine (Checkov) -> LLM analysis -> merge findings -> LLM fix
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from iac_scanner.models import Finding
from iac_scanner.orchestration.runner import PipelineResult, run_pipeline
from iac_scanner.rules import is_available, run_rule_engine
from iac_scanner.scanners.base import IacScanner

if TYPE_CHECKING:
    from iac_scanner.llm.providers import LLMClient, Provider

logger = logging.getLogger(__name__)


def _dedupe_findings(rule_findings: list[Finding], llm_findings: list[Finding]) -> list[Finding]:
    """Preserve rule findings; append LLM findings that don't duplicate a rule one.

    Dedupe key prefers rule_id; falls back to normalized title + location.
    """
    seen_rule_ids = {f.rule_id for f in rule_findings if f.rule_id}
    seen_signatures = {(f.title.strip().lower(), f.location.strip().lower()) for f in rule_findings}

    merged: list[Finding] = list(rule_findings)
    for f in llm_findings:
        if f.rule_id and f.rule_id in seen_rule_ids:
            continue
        sig = (f.title.strip().lower(), f.location.strip().lower())
        if sig in seen_signatures:
            continue
        merged.append(f)
        seen_signatures.add(sig)
    return merged


def run_hybrid_pipeline(
    scanner: IacScanner,
    *,
    engine: str = "auto",
    provider: Provider | None = None,
    skip_fix: bool = False,
    analysis_client: LLMClient | None = None,
    fix_client: LLMClient | None = None,
) -> PipelineResult:
    """Run the hybrid pipeline: rule pre-pass + LLM augment + fix.

    If the rule engine is unavailable AND engine='auto', falls back gracefully
    to the LLM-only pipeline (returns same PipelineResult shape).
    """
    if engine != "none" and not is_available(engine):
        if engine == "auto":
            logger.info("Rule engine unavailable; falling back to LLM-only pipeline.")
            engine = "none"
        else:
            # Non-auto but unavailable: let the caller see the error.
            pass

    rule_findings: list[Finding] = []
    if engine not in ("none", "auto") or (engine == "auto" and is_available("checkov")):
        try:
            rule_findings = run_rule_engine(
                scanner.base_path,
                scanner.iac_type,
                engine="checkov" if engine == "auto" else engine,
            )
            logger.info("Rule engine produced %d findings", len(rule_findings))
        except Exception as e:  # noqa: BLE001
            logger.warning("Rule engine failed: %s. Continuing with LLM-only.", e)

    # LLM pipeline (may itself skip if content is empty)
    llm_result = run_pipeline(
        scanner,
        provider=provider,
        skip_fix=skip_fix,
        analysis_client=analysis_client,
        fix_client=fix_client,
    )

    merged = _dedupe_findings(rule_findings, llm_result.findings)

    return PipelineResult(
        scan_result=llm_result.scan_result,
        findings=merged,
        findings_raw=llm_result.findings_raw,  # keep LLM raw for debugging
        fixed_code=llm_result.fixed_code,
        prompt_version=llm_result.prompt_version,
        provider=llm_result.provider,
        analysis_model=llm_result.analysis_model,
        fix_model=llm_result.fix_model,
        cache_hits=llm_result.cache_hits,
        cost_estimates=llm_result.cost_estimates,
    )
