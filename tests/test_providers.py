"""Unit tests for llm/providers.py — auto-detect + factory behavior.

Actual network calls to LLMs are *not* exercised here. We assert that the right
factory is picked and the right error surfaces. Runtime tests against real
providers live in the nightly E2E workflow.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from iac_scanner.llm import ProviderError, auto_detect_provider, make_llm


class TestAutoDetectProvider:
    def test_explicit_iac_provider_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAC_PROVIDER", "openai")
        monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")
        assert auto_detect_provider() == "openai"

    def test_invalid_IAC_PROVIDER_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAC_PROVIDER", "magic-ai")
        with pytest.raises(ProviderError, match="Unknown IAC_PROVIDER"):
            auto_detect_provider()

    def test_prefers_ollama_when_reachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        with patch("iac_scanner.llm.providers._ollama_reachable", return_value=True):
            assert auto_detect_provider() == "ollama"

    def test_falls_back_to_github_when_ollama_down(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")
        # Ollama unreachable from autouse fixture; GITHUB_TOKEN present
        assert auto_detect_provider() == "github"

    def test_falls_back_to_openai_when_only_openai_key_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        assert auto_detect_provider() == "openai"

    def test_falls_back_to_anthropic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        assert auto_detect_provider() == "anthropic"

    def test_raises_when_nothing_available(self) -> None:
        # autouse fixture has cleared all provider env
        with pytest.raises(ProviderError, match="No LLM provider available"):
            auto_detect_provider()


class TestMakeLlm:
    def test_make_openai_requires_key(self) -> None:
        with pytest.raises(ProviderError, match="OPENAI_API_KEY"):
            make_llm("openai", "analysis")

    def test_make_anthropic_requires_key(self) -> None:
        with pytest.raises(ProviderError, match="ANTHROPIC_API_KEY"):
            make_llm("anthropic", "analysis")

    def test_make_github_requires_token(self) -> None:
        with pytest.raises(ProviderError, match="GITHUB_TOKEN"):
            make_llm("github", "analysis")

    def test_make_github_with_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
        client = make_llm("github", "analysis")
        assert client.provider == "github"
        assert client.role == "analysis"

    def test_make_openai_with_key_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        client = make_llm("openai", "analysis")
        assert client.provider == "openai"
        assert client.role == "analysis"
        assert client.model  # default model populated

    def test_model_override_via_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("IAC_ANALYSIS_MODEL", "gpt-4o")
        client = make_llm("openai", "analysis")
        assert client.model == "gpt-4o"
