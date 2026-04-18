"""Integration tests for orchestration/runner.py with mocked LLMClients.

These cover the full pipeline (scan -> analysis -> fix) without hitting any
real LLM API. They exercise cache, cost estimation, and PipelineResult wiring.
"""

from __future__ import annotations

import pytest

from iac_scanner.factory import create_scanner
from iac_scanner.orchestration.runner import _serialize_findings, run_pipeline
from tests.conftest import FakeLLMClient


class TestSerializeFindings:
    def test_roundtrips_empty_list(self) -> None:
        from iac_scanner.models import FindingsList

        assert _serialize_findings(FindingsList(root=[])) == "[]"

    def test_omits_none_fields(self, fake_analysis_client_with_findings: FakeLLMClient) -> None:
        findings = fake_analysis_client_with_findings._structured_response
        assert findings is not None
        s = _serialize_findings(findings)
        assert '"severity":"high"' in s
        # None fields (e.g. cwe, framework) are omitted from the JSON
        assert "cwe" not in s


class TestRunPipeline:
    def test_happy_path_with_findings_and_fix(
        self,
        fake_analysis_client_with_findings: FakeLLMClient,
        fake_fix_client_with_code: FakeLLMClient,
    ) -> None:
        scanner = create_scanner("samples/tf")
        result = run_pipeline(
            scanner,
            analysis_client=fake_analysis_client_with_findings,
            fix_client=fake_fix_client_with_code,
        )
        assert fake_analysis_client_with_findings.calls == 1
        assert fake_fix_client_with_code.calls == 1
        assert len(result.findings) == 2
        assert result.fixed_code
        assert "aws_s3_bucket" in result.fixed_code

    def test_skip_fix_does_not_call_fix_client(
        self,
        fake_analysis_client_with_findings: FakeLLMClient,
        fake_fix_client_with_code: FakeLLMClient,
    ) -> None:
        scanner = create_scanner("samples/tf")
        result = run_pipeline(
            scanner,
            analysis_client=fake_analysis_client_with_findings,
            fix_client=fake_fix_client_with_code,
            skip_fix=True,
        )
        assert fake_fix_client_with_code.calls == 0
        assert result.fixed_code == ""

    def test_cache_hit_avoids_second_llm_call(
        self,
        fake_analysis_client_with_findings: FakeLLMClient,
    ) -> None:
        scanner = create_scanner("samples/tf")
        # First run — LLM called once, result cached
        run_pipeline(
            scanner,
            analysis_client=fake_analysis_client_with_findings,
            skip_fix=True,
        )
        first_calls = fake_analysis_client_with_findings.calls
        # Second run with the SAME client instance (same provider+model) —
        # cache should short-circuit and not invoke the LLM again.
        run_pipeline(
            scanner,
            analysis_client=fake_analysis_client_with_findings,
            skip_fix=True,
        )
        assert fake_analysis_client_with_findings.calls == first_calls

    def test_no_cache_env_bypasses_cache(
        self,
        fake_analysis_client_with_findings: FakeLLMClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("IAC_NO_CACHE", "1")
        scanner = create_scanner("samples/tf")
        run_pipeline(
            scanner,
            analysis_client=fake_analysis_client_with_findings,
            skip_fix=True,
        )
        run_pipeline(
            scanner,
            analysis_client=fake_analysis_client_with_findings,
            skip_fix=True,
        )
        # Both runs should hit the LLM when cache is disabled
        assert fake_analysis_client_with_findings.calls == 2

    def test_pipeline_result_carries_provider_and_model(
        self,
        fake_analysis_client_with_findings: FakeLLMClient,
    ) -> None:
        scanner = create_scanner("samples/tf")
        result = run_pipeline(
            scanner,
            analysis_client=fake_analysis_client_with_findings,
            skip_fix=True,
        )
        assert result.provider == fake_analysis_client_with_findings.provider
        assert result.analysis_model == fake_analysis_client_with_findings.model

    def test_cost_estimates_populated_when_llm_called(
        self,
        fake_analysis_client_with_findings: FakeLLMClient,
    ) -> None:
        scanner = create_scanner("samples/tf")
        result = run_pipeline(
            scanner,
            analysis_client=fake_analysis_client_with_findings,
            skip_fix=True,
        )
        assert len(result.cost_estimates) >= 1
