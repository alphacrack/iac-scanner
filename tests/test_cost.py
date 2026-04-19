"""Unit tests for cost.py — tokenization, pricing, budget enforcement."""

from __future__ import annotations

import pytest

from iac_scanner.cost import (
    CostBudgetExceeded,
    CostEstimate,
    budget_cap,
    count_input_tokens,
    enforce_budget,
    estimate,
)


class TestCountInputTokens:
    def test_openai_uses_tiktoken_or_fallback(self) -> None:
        # Either tiktoken is installed (token count will be ~5 for this text)
        # or we fall back to len/4. Both should return a positive int.
        n = count_input_tokens("hello world how are you today", "openai", "gpt-4o-mini")
        assert n > 0

    def test_anthropic_uses_char_approximation(self) -> None:
        text = "a" * 40  # 40 chars / 4 = 10 tokens
        assert count_input_tokens(text, "anthropic", "claude-3-5-haiku-20241022") == 10

    def test_ollama_returns_nonzero(self) -> None:
        # Ollama falls through to char/4 heuristic.
        n = count_input_tokens("a" * 100, "ollama", "llama3.1:8b")
        assert n >= 1


class TestEstimate:
    def test_ollama_costs_zero(self) -> None:
        est = estimate("a" * 1000, provider="ollama", model="llama3.1:8b", call_kind="analysis")
        assert est.usd_est == 0.0
        assert est.provider == "ollama"

    def test_github_costs_zero(self) -> None:
        est = estimate("a" * 1000, provider="github", model="gpt-4o-mini", call_kind="analysis")
        assert est.usd_est == 0.0

    def test_openai_gpt4o_mini_is_cheap(self) -> None:
        est = estimate("a" * 4000, provider="openai", model="gpt-4o-mini", call_kind="analysis")
        # ~1000 input tokens × $0.15/M + ~500 output tokens × $0.60/M ≈ $0.00045
        assert 0.0 < est.usd_est < 0.01

    def test_unknown_model_falls_back_to_wildcard_pricing(self) -> None:
        est = estimate(
            "a" * 4000,
            provider="openai",
            model="gpt-9999-futuristic",
            call_kind="analysis",
        )
        # Wildcard is (5.00, 15.00) per 1M — conservative upper bound.
        assert est.usd_est > 0


class TestBudgetEnforcement:
    def test_no_cap_means_no_enforcement(self) -> None:
        enforce_budget(
            [
                CostEstimate(
                    provider="openai",
                    model="gpt-4o",
                    call_kind="fix",
                    input_tokens=1_000_000,
                    output_tokens_est=2_000_000,
                    usd_est=999.0,
                )
            ]
        )  # does not raise

    def test_budget_raises_when_exceeded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAC_MAX_SPEND_USD", "0.01")
        with pytest.raises(CostBudgetExceeded):
            enforce_budget(
                [
                    CostEstimate(
                        provider="openai",
                        model="gpt-4o",
                        call_kind="fix",
                        input_tokens=100000,
                        output_tokens_est=100000,
                        usd_est=1.50,
                    )
                ]
            )

    def test_budget_ok_when_under_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAC_MAX_SPEND_USD", "5.00")
        enforce_budget(
            [
                CostEstimate(
                    provider="openai",
                    model="gpt-4o-mini",
                    call_kind="analysis",
                    input_tokens=1000,
                    output_tokens_est=500,
                    usd_est=0.001,
                )
            ]
        )  # does not raise

    def test_budget_cap_parses_float(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAC_MAX_SPEND_USD", "0.50")
        assert budget_cap() == 0.50

    def test_budget_cap_ignores_invalid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAC_MAX_SPEND_USD", "not-a-number")
        assert budget_cap() is None
