"""Shared pytest fixtures: mocked LLMClient, temp cache dir, env isolation."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from iac_scanner.models import Finding, FindingsList


@pytest.fixture(autouse=True)
def isolate_cache_dir(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Redirect the cache dir to a fresh tmp path for every test.

    Prevents tests from polluting the user's real `~/.cache/iac-scanner/` and
    prevents cache hits from leaking state between tests.
    """
    monkeypatch.setenv("IAC_CACHE_DIR", str(tmp_path / "iac-cache"))
    yield


@pytest.fixture(autouse=True)
def clear_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear provider-related env vars so tests have deterministic auto-detect."""
    for var in (
        "IAC_PROVIDER",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "IAC_ANALYSIS_AI",
        "IAC_FIX_AI",
        "IAC_NO_CACHE",
        "IAC_MAX_SPEND_USD",
        "IAC_MAX_INPUT_BYTES",
        "IAC_NO_REDACT",
    ):
        monkeypatch.delenv(var, raising=False)
    # Point Ollama detector at a port that definitely won't respond
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")


@dataclass
class FakeLLMClient:
    """Test double for LLMClient — deterministic responses, no network."""

    provider: str = "openai"
    role: str = "analysis"
    model: str = "gpt-4o-mini"
    _structured_response: FindingsList | None = None
    _text_response: str = ""
    calls: int = 0

    def invoke_structured(self, prompt: Any, schema: type, variables: dict[str, Any]) -> Any:
        self.calls += 1
        if self._structured_response is None:
            return schema.model_validate([])
        return self._structured_response

    def invoke_text(self, prompt: Any, variables: dict[str, Any]) -> str:
        self.calls += 1
        return self._text_response


@pytest.fixture
def fake_analysis_client_empty() -> FakeLLMClient:
    """LLMClient that always returns empty findings."""
    return FakeLLMClient(
        role="analysis",
        _structured_response=FindingsList(root=[]),
    )


@pytest.fixture
def fake_analysis_client_with_findings() -> FakeLLMClient:
    """LLMClient that returns a canned list of findings."""
    return FakeLLMClient(
        role="analysis",
        _structured_response=FindingsList(
            root=[
                Finding(
                    severity="high",  # type: ignore[arg-type]
                    title="S3 bucket is public",
                    description="Bucket ACL permits public read.",
                    location="main.tf:10",
                ),
                Finding(
                    severity="medium",  # type: ignore[arg-type]
                    title="IAM role too permissive",
                    description="Role grants * on * resources.",
                    location="main.tf:25",
                ),
            ]
        ),
    )


@pytest.fixture
def fake_fix_client_with_code() -> FakeLLMClient:
    """LLMClient whose invoke_text returns canned fixed code."""
    return FakeLLMClient(
        role="fix",
        provider="openai",
        model="gpt-4o",
        _text_response=('# --- main.tf ---\nresource "aws_s3_bucket" "example" {\n  bucket = "my-secure-bucket"\n}\n'),
    )
