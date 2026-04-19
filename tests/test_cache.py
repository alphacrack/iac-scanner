"""Unit tests for cache.py — key derivation, get/put, TTL."""

from __future__ import annotations

import pytest

from iac_scanner.cache import (
    DEFAULT_TTL_SECONDS,
    CacheKey,
    cache_root,
    get,
    is_disabled,
    put,
)


class TestCacheKey:
    def test_same_inputs_same_digest(self) -> None:
        k1 = CacheKey("analysis", "code", "openai", "gpt-4o", "v1")
        k2 = CacheKey("analysis", "code", "openai", "gpt-4o", "v1")
        assert k1.digest() == k2.digest()

    def test_different_content_different_digest(self) -> None:
        k1 = CacheKey("analysis", "code A", "openai", "gpt-4o", "v1")
        k2 = CacheKey("analysis", "code B", "openai", "gpt-4o", "v1")
        assert k1.digest() != k2.digest()

    def test_different_provider_different_digest(self) -> None:
        k1 = CacheKey("analysis", "code", "openai", "gpt-4o", "v1")
        k2 = CacheKey("analysis", "code", "anthropic", "gpt-4o", "v1")
        assert k1.digest() != k2.digest()

    def test_different_model_different_digest(self) -> None:
        k1 = CacheKey("analysis", "code", "openai", "gpt-4o", "v1")
        k2 = CacheKey("analysis", "code", "openai", "gpt-4o-mini", "v1")
        assert k1.digest() != k2.digest()

    def test_prompt_version_is_part_of_key(self) -> None:
        k1 = CacheKey("analysis", "code", "openai", "gpt-4o", "v1")
        k2 = CacheKey("analysis", "code", "openai", "gpt-4o", "v2")
        assert k1.digest() != k2.digest()

    def test_call_kind_is_part_of_key(self) -> None:
        k1 = CacheKey("analysis", "code", "openai", "gpt-4o", "v1")
        k2 = CacheKey("fix", "code", "openai", "gpt-4o", "v1")
        assert k1.digest() != k2.digest()

    def test_extra_field_is_part_of_key(self) -> None:
        k1 = CacheKey("fix", "code", "openai", "gpt-4o", "v1", extra="findings-A")
        k2 = CacheKey("fix", "code", "openai", "gpt-4o", "v1", extra="findings-B")
        assert k1.digest() != k2.digest()


class TestGetPut:
    def test_roundtrip(self) -> None:
        key = CacheKey("analysis", "some code", "openai", "gpt-4o", "v1")
        assert get(key) is None
        put(key, {"findings": ["a", "b"]})
        assert get(key) == {"findings": ["a", "b"]}

    def test_miss_returns_none(self) -> None:
        key = CacheKey("analysis", "unseen", "openai", "gpt-4o", "v1")
        assert get(key) is None

    def test_ttl_expiry(self) -> None:
        key = CacheKey("analysis", "x", "openai", "gpt-4o", "v1")
        put(key, "value")
        assert get(key) == "value"
        # With zero TTL the stored entry is always considered stale
        assert get(key, ttl_seconds=0) is None

    def test_default_ttl_is_30_days(self) -> None:
        assert DEFAULT_TTL_SECONDS == 30 * 24 * 3600


class TestDisabled:
    def test_respects_IAC_NO_CACHE(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAC_NO_CACHE", "1")
        assert is_disabled() is True
        key = CacheKey("analysis", "x", "openai", "gpt-4o", "v1")
        put(key, "value")  # put is a no-op when disabled
        # Read is also no-op
        monkeypatch.delenv("IAC_NO_CACHE")
        assert get(key) is None  # confirm nothing was written

    def test_enabled_by_default(self) -> None:
        assert is_disabled() is False


class TestCacheRoot:
    def test_honors_IAC_CACHE_DIR(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        monkeypatch.setenv("IAC_CACHE_DIR", str(tmp_path / "custom"))
        assert cache_root() == tmp_path / "custom"

    def test_honors_XDG_CACHE_HOME(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        monkeypatch.delenv("IAC_CACHE_DIR", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        assert cache_root() == tmp_path / "xdg" / "iac-scanner"
