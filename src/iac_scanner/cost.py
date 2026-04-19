"""Cost guardrail: pre-flight token estimate + projected USD cost per call.

Rough estimates are fine — they exist to catch accidents (a 2MB Terraform
module mistakenly passed in) before they cost $20. Per-run budget cap is set
via `IAC_MAX_SPEND_USD` (float) or `--max-spend`.

Pricing table below is a point-in-time snapshot (reviewed 2026-04). Providers
change prices; the table is easy to update and is NOT the source of truth for
billing. Ollama and GitHub Models are $0.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)

# Input / output prices in USD per 1,000,000 tokens.
# Keys are (provider, model_prefix). First-match-wins on prefix.
_PRICES_PER_MILLION: dict[tuple[str, str], tuple[float, float]] = {
    # OpenAI (and GitHub Models free tier — treat as OpenAI pricing for the cap math,
    # GitHub Models themselves are billed as $0 in _price_for below when provider='github').
    ("openai", "gpt-4o-mini"): (0.15, 0.60),
    ("openai", "gpt-4o"): (2.50, 10.00),
    ("openai", "gpt-4"): (30.00, 60.00),
    ("openai", "o1"): (15.00, 60.00),
    ("openai", "o3"): (10.00, 40.00),
    # Anthropic
    ("anthropic", "claude-3-5-haiku"): (0.80, 4.00),
    ("anthropic", "claude-3-5-sonnet"): (3.00, 15.00),
    ("anthropic", "claude-3-opus"): (15.00, 75.00),
    # Default fallbacks — conservative upper bounds so the guard errs on caution.
    ("openai", "*"): (5.00, 15.00),
    ("anthropic", "*"): (5.00, 25.00),
}

# Estimated output-to-input token ratio by call kind. Conservative upper bound.
_OUTPUT_MULT: dict[str, float] = {
    "analysis": 0.5,  # structured JSON is typically short vs. input
    "fix": 1.2,  # regenerated code is roughly the same size as input, rounded up
}


class CostBudgetExceeded(RuntimeError):
    """Raised when projected LLM spend exceeds the user-configured budget."""


@dataclass(frozen=True)
class CostEstimate:
    provider: str
    model: str
    call_kind: str
    input_tokens: int
    output_tokens_est: int
    usd_est: float


def _count_tokens_openai_compat(text: str, model: str) -> int:
    """Use tiktoken's encoder for OpenAI-compatible models. Falls back to 4 chars/token."""
    try:
        import tiktoken

        try:
            enc = tiktoken.encoding_for_model(model)
        except KeyError:
            # New model not yet in tiktoken's registry — use the broadest codec.
            enc = tiktoken.get_encoding("o200k_base")
        return len(enc.encode(text))
    except Exception:  # noqa: BLE001 — tiktoken is optional; do not block on it.
        return max(1, len(text) // 4)


def _count_tokens_anthropic(text: str) -> int:
    """Anthropic's tokenizer ships with the SDK but loads slow; use char-based approximation.

    4 chars/token is the conservative industry rule-of-thumb for Claude.
    """
    return max(1, len(text) // 4)


def count_input_tokens(text: str, provider: str, model: str) -> int:
    """Estimate input token count for the given provider/model."""
    if provider in ("openai", "github"):
        return _count_tokens_openai_compat(text, model)
    if provider == "anthropic":
        return _count_tokens_anthropic(text)
    return max(1, len(text) // 4)  # ollama or unknown


def _price_for(provider: str, model: str) -> tuple[float, float]:
    """Return (input_price_per_1M, output_price_per_1M) USD for provider/model."""
    if provider == "ollama":
        return (0.0, 0.0)
    if provider == "github":
        # GitHub Models free tier — cap math uses $0. Warn users in docs that rate
        # limits apply. If GitHub later charges, update this branch.
        return (0.0, 0.0)

    # Prefix match: find the longest model-prefix that matches.
    best: tuple[float, float] | None = None
    best_len = -1
    for (prov, prefix), price in _PRICES_PER_MILLION.items():
        if prov != provider:
            continue
        if prefix == "*" or model.startswith(prefix):
            prefix_len = -1 if prefix == "*" else len(prefix)
            if prefix_len > best_len:
                best = price
                best_len = prefix_len
    return best or (5.0, 15.0)


def estimate(
    text: str,
    *,
    provider: str,
    model: str,
    call_kind: Literal["analysis", "fix"],
) -> CostEstimate:
    """Pre-flight estimate of input/output tokens + USD cost for a single LLM call."""
    input_tokens = count_input_tokens(text, provider, model)
    output_tokens = int(input_tokens * _OUTPUT_MULT.get(call_kind, 1.0))
    in_price, out_price = _price_for(provider, model)
    usd = (input_tokens * in_price + output_tokens * out_price) / 1_000_000
    return CostEstimate(
        provider=provider,
        model=model,
        call_kind=call_kind,
        input_tokens=input_tokens,
        output_tokens_est=output_tokens,
        usd_est=usd,
    )


def budget_cap() -> float | None:
    """Return the configured per-run budget cap in USD, or None if unset."""
    raw = os.environ.get("IAC_MAX_SPEND_USD")
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        logger.warning("Invalid IAC_MAX_SPEND_USD=%r; ignoring", raw)
        return None


def enforce_budget(estimates: list[CostEstimate]) -> None:
    """Sum projected USD across estimates and raise if it exceeds the configured cap."""
    cap = budget_cap()
    if cap is None:
        return
    projected = sum(e.usd_est for e in estimates)
    if projected > cap:
        breakdown = ", ".join(f"{e.call_kind}:${e.usd_est:.4f}" for e in estimates)
        raise CostBudgetExceeded(
            f"Projected LLM spend ${projected:.4f} exceeds cap ${cap:.4f} "
            f"(IAC_MAX_SPEND_USD). Breakdown: {breakdown}. "
            f"Use --no-fix, --scan-only, --provider=ollama, or raise --max-spend."
        )
