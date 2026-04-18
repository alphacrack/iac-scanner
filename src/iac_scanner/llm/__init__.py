"""LLM provider abstraction for iac-scanner.

`make_llm(provider, role)` returns an LLMClient wrapping a LangChain chat model.
Downstream code depends on LLMClient, not on LangChain directly, so swapping
to raw openai/anthropic SDKs later is a one-file change.
"""

from iac_scanner.llm.providers import (
    AUTO_DETECT_ORDER,
    LLMClient,
    ProviderError,
    auto_detect_provider,
    make_llm,
)

__all__ = [
    "AUTO_DETECT_ORDER",
    "LLMClient",
    "ProviderError",
    "auto_detect_provider",
    "make_llm",
]
