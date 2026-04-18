"""Unit tests for orchestration/hybrid.py — finding dedup + graceful fallback."""

from __future__ import annotations

from unittest.mock import patch

from iac_scanner.factory import create_scanner
from iac_scanner.models import Finding, FindingSource, Severity
from iac_scanner.orchestration.hybrid import _dedupe_findings, run_hybrid_pipeline
from iac_scanner.orchestration.runner import PipelineResult
from tests.conftest import FakeLLMClient

SAMPLES = "samples"


def _rule(**kw: object) -> Finding:
    kw.setdefault("severity", Severity.HIGH)
    kw.setdefault("title", "Rule finding")
    kw.setdefault("description", "A rule engine finding")
    kw.setdefault("location", "main.tf:5")
    kw.setdefault("source", FindingSource.CHECKOV)
    return Finding(**kw)  # type: ignore[arg-type]


def _llm(**kw: object) -> Finding:
    kw.setdefault("severity", Severity.MEDIUM)
    kw.setdefault("title", "LLM finding")
    kw.setdefault("description", "An LLM-spotted issue")
    kw.setdefault("location", "main.tf:20")
    kw.setdefault("source", FindingSource.LLM)
    return Finding(**kw)  # type: ignore[arg-type]


class TestDedupe:
    def test_preserves_rule_findings_first(self) -> None:
        rule = [_rule(rule_id="CKV_AWS_20", title="S3 public")]
        llm = [_llm(title="Something else", location="main.tf:50")]
        merged = _dedupe_findings(rule, llm)
        assert merged[0].source == FindingSource.CHECKOV
        assert merged[-1].source == FindingSource.LLM

    def test_drops_llm_duplicate_by_rule_id(self) -> None:
        rule = [_rule(rule_id="CKV_AWS_20", title="S3 public")]
        llm = [_llm(rule_id="CKV_AWS_20", title="S3 public ACL")]
        merged = _dedupe_findings(rule, llm)
        assert len(merged) == 1
        assert merged[0].source == FindingSource.CHECKOV

    def test_drops_llm_duplicate_by_title_and_location(self) -> None:
        rule = [_rule(title="S3 bucket public", location="main.tf:10")]
        llm = [_llm(title="S3 bucket public", location="main.tf:10")]
        merged = _dedupe_findings(rule, llm)
        assert len(merged) == 1
        assert merged[0].source == FindingSource.CHECKOV

    def test_keeps_llm_finding_with_unique_location(self) -> None:
        rule = [_rule(title="S3 bucket public", location="main.tf:10")]
        llm = [_llm(title="S3 bucket public", location="main.tf:50")]
        merged = _dedupe_findings(rule, llm)
        assert len(merged) == 2

    def test_empty_inputs(self) -> None:
        assert _dedupe_findings([], []) == []


class TestRunHybridFallback:
    def test_engine_none_skips_rule_pass(
        self,
        tmp_path,
        fake_analysis_client_empty: FakeLLMClient,
    ) -> None:
        scanner = create_scanner("samples/tf")
        with patch("iac_scanner.orchestration.hybrid.is_available", return_value=False):
            result = run_hybrid_pipeline(
                scanner,
                engine="none",
                skip_fix=True,
                analysis_client=fake_analysis_client_empty,
            )
        assert isinstance(result, PipelineResult)
        assert fake_analysis_client_empty.calls >= 1

    def test_engine_auto_falls_back_to_llm_when_unavailable(
        self,
        fake_analysis_client_with_findings: FakeLLMClient,
    ) -> None:
        scanner = create_scanner("samples/tf")
        with patch("iac_scanner.orchestration.hybrid.is_available", return_value=False):
            result = run_hybrid_pipeline(
                scanner,
                engine="auto",
                skip_fix=True,
                analysis_client=fake_analysis_client_with_findings,
            )
        # LLM findings survive even without rule-engine findings
        assert len(result.findings) == 2

    def test_rule_findings_are_merged_when_available(
        self,
        fake_analysis_client_with_findings: FakeLLMClient,
    ) -> None:
        scanner = create_scanner("samples/tf")
        canned_rule_findings = [_rule(rule_id="CKV_AWS_20", title="S3 public ACL")]
        with (
            patch("iac_scanner.orchestration.hybrid.is_available", return_value=True),
            patch(
                "iac_scanner.orchestration.hybrid.run_rule_engine",
                return_value=canned_rule_findings,
            ),
        ):
            result = run_hybrid_pipeline(
                scanner,
                engine="checkov",
                skip_fix=True,
                analysis_client=fake_analysis_client_with_findings,
            )
        rule_ids = {f.rule_id for f in result.findings if f.rule_id}
        assert "CKV_AWS_20" in rule_ids
        # Original 2 LLM findings + 1 rule finding, no dupes
        assert len(result.findings) == 3
