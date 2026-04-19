"""LLM provider factory. Role-aware (analysis vs fix). Keyless paths first-class.

Providers:
    openai       — requires OPENAI_API_KEY
    anthropic    — requires ANTHROPIC_API_KEY
    github       — requires GITHUB_TOKEN only (free for GitHub-authenticated users)
    ollama       — no key, requires local Ollama server at OLLAMA_HOST or localhost:11434

The auto-detect chain (used when --provider is omitted) picks in order:
    explicit IAC_PROVIDER env → ollama (if reachable) → github (if GITHUB_TOKEN)
    → openai (if OPENAI_API_KEY) → anthropic (if ANTHROPIC_API_KEY) → ProviderError.

Design note:
    LLMClient is a thin dataclass wrapping LangChain's BaseChatModel. Orchestration
    code calls `.invoke_structured(schema, variables)` — this isolates the LangChain
    dependency to this file so a future switch to raw openai/anthropic SDKs is contained.
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypeVar

from pydantic import BaseModel

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from langchain_core.prompts import ChatPromptTemplate

Provider = Literal["openai", "anthropic", "github", "ollama"]
Role = Literal["analysis", "fix"]

AUTO_DETECT_ORDER: list[Provider] = ["ollama", "github", "openai", "anthropic"]

# Default models per provider × role. Overridable via IAC_{ANALYSIS,FIX}_MODEL env vars.
DEFAULT_MODELS: dict[tuple[Provider, Role], str] = {
    ("openai", "analysis"): "gpt-4o-mini",
    ("openai", "fix"): "gpt-4o",
    ("anthropic", "analysis"): "claude-3-5-haiku-20241022",
    ("anthropic", "fix"): "claude-3-5-sonnet-20241022",
    # GitHub Models uses OpenAI-compatible naming. gpt-4o-mini is free-tier eligible.
    ("github", "analysis"): "gpt-4o-mini",
    ("github", "fix"): "gpt-4o",
    # Ollama: small-ish model that fits on a laptop, code-aware.
    ("ollama", "analysis"): "qwen2.5-coder:7b-instruct",
    ("ollama", "fix"): "qwen2.5-coder:7b-instruct",
}

GITHUB_MODELS_BASE_URL = "https://models.inference.ai.azure.com"

T = TypeVar("T", bound=BaseModel)


class ProviderError(RuntimeError):
    """Raised when no viable LLM provider can be constructed."""


@dataclass
class LLMClient:
    """Thin wrapper around a LangChain chat model.

    Keep this interface small. Downstream code calls `.invoke_structured(schema, vars)`
    — everything else is a LangChain implementation detail.
    """

    provider: Provider
    role: Role
    model: str
    _llm: BaseChatModel  # populated by make_llm; not for external use

    def invoke_structured(
        self,
        prompt: ChatPromptTemplate,
        schema: type[T],
        variables: dict[str, Any],
    ) -> T:
        """Invoke the chain with structured output. Raises if the LLM returns invalid shape.

        One retry is handled at the orchestration layer, not here, so this stays simple.
        """
        structured_llm = self._llm.with_structured_output(schema)
        chain = prompt | structured_llm
        result = chain.invoke(variables)
        if not isinstance(result, schema):
            raise ProviderError(
                f"LLM {self.provider}:{self.model} returned unexpected type "
                f"{type(result).__name__}, expected {schema.__name__}"
            )
        return result

    def invoke_text(self, prompt: ChatPromptTemplate, variables: dict[str, Any]) -> str:
        """Invoke the chain expecting a plain-text response (used for fix/codegen)."""
        from langchain_core.output_parsers import StrOutputParser

        chain = prompt | self._llm | StrOutputParser()
        out = chain.invoke(variables)
        return str(out)


def _model_for(provider: Provider, role: Role) -> str:
    """Resolve the model name: role-specific env → provider default."""
    env_var = f"IAC_{role.upper()}_MODEL"
    if override := os.environ.get(env_var):
        return override
    return DEFAULT_MODELS[(provider, role)]


def _temperature_for(role: Role) -> float:
    """Temperature=0 for determinism. Fix role still gets 0 — we want reproducible fixes."""
    return 0.0


def _make_openai(
    role: Role, *, api_key: str | None = None, base_url: str | None = None, model: str | None = None
) -> BaseChatModel:
    """Create a ChatOpenAI. Also used for GitHub Models (OpenAI-compatible endpoint)."""
    from langchain_openai import ChatOpenAI

    model = model or _model_for("openai", role)
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        raise ProviderError("OPENAI_API_KEY not set")
    kwargs: dict[str, Any] = {
        "model": model,
        "api_key": key,
        "temperature": _temperature_for(role),
        # Pass `seed` as a top-level kwarg — langchain-openai surfaces it explicitly.
        "seed": 42,
    }
    if base_url:
        kwargs["base_url"] = base_url
    return ChatOpenAI(**kwargs)


def _make_anthropic(role: Role) -> BaseChatModel:
    from langchain_anthropic import ChatAnthropic
    from pydantic import SecretStr

    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise ProviderError("ANTHROPIC_API_KEY not set")
    model = _model_for("anthropic", role)
    return ChatAnthropic(
        model_name=model,
        api_key=SecretStr(key),
        temperature=_temperature_for(role),
        timeout=60.0,
        stop=None,
    )


def _make_github(role: Role) -> BaseChatModel:
    """GitHub Models — free tier for GitHub-authenticated users. OpenAI-compatible API."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        raise ProviderError(
            "GITHUB_TOKEN not set. Run `gh auth login` or set GITHUB_TOKEN explicitly "
            "to use the free GitHub Models provider."
        )
    model = _model_for("github", role)
    return _make_openai(role, api_key=token, base_url=GITHUB_MODELS_BASE_URL, model=model)


def _make_ollama(role: Role) -> BaseChatModel:
    try:
        from langchain_ollama import ChatOllama
    except ImportError as e:
        raise ProviderError(
            "langchain-ollama is not installed. Run `pip install iac-scanner[local]` to enable the Ollama provider."
        ) from e

    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    model = _model_for("ollama", role)
    # langchain-ollama is untyped; mypy can't narrow the return — cast to BaseChatModel.
    chat: BaseChatModel = ChatOllama(
        model=model,
        base_url=host,
        temperature=_temperature_for(role),
    )
    return chat


def _ollama_reachable(timeout: float = 0.5) -> bool:
    """Quick liveness probe for auto-detect. No exception propagation.

    Only http(s) schemes are accepted for OLLAMA_HOST; this prevents a malicious
    `OLLAMA_HOST=file:///etc/passwd` from tricking the probe into reading a
    local file.
    """
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    if not host.startswith(("http://", "https://")):
        return False
    try:
        with urllib.request.urlopen(  # noqa: S310 — scheme guarded above; nosec B310
            f"{host}/api/tags",
            timeout=timeout,
        ) as resp:
            status: int = int(resp.status)
            return 200 <= status < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def auto_detect_provider() -> Provider:
    """Pick a viable provider from the environment. See module docstring for order.

    Raises ProviderError if nothing works so the caller can print a helpful hint.
    """
    if explicit := os.environ.get("IAC_PROVIDER"):
        explicit_lower = explicit.lower()
        if explicit_lower in ("openai", "anthropic", "github", "ollama"):
            return explicit_lower  # type: ignore[return-value]
        raise ProviderError(f"Unknown IAC_PROVIDER={explicit!r}. Valid: openai, anthropic, github, ollama.")

    if _ollama_reachable():
        return "ollama"
    if os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"):
        return "github"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"

    raise ProviderError(
        "No LLM provider available. Options:\n"
        "  - Start Ollama (local, free): `ollama serve` + `pip install iac-scanner[local]`\n"
        "  - Use GitHub Models (free for GitHub users): `export GITHUB_TOKEN=$(gh auth token)`\n"
        "  - Use OpenAI: `export OPENAI_API_KEY=sk-...`\n"
        "  - Use Anthropic: `export ANTHROPIC_API_KEY=sk-ant-...`\n"
        "  - Or skip AI entirely: `iac-scan scan <path> --scan-only`"
    )


def make_llm(provider: Provider | None, role: Role) -> LLMClient:
    """Build an LLMClient for the given role. If provider is None, auto-detect.

    This is the only entry point the rest of the codebase should use.
    """
    resolved: Provider = provider if provider is not None else auto_detect_provider()

    if resolved == "openai":
        llm = _make_openai(role)
    elif resolved == "anthropic":
        llm = _make_anthropic(role)
    elif resolved == "github":
        llm = _make_github(role)
    elif resolved == "ollama":
        llm = _make_ollama(role)
    else:  # pragma: no cover — Literal exhausted above
        raise ProviderError(f"Unknown provider: {resolved}")

    return LLMClient(
        provider=resolved,
        role=role,
        model=_model_for(resolved, role),
        _llm=llm,
    )
