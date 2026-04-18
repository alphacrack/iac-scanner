"""Content-addressed response cache.

Cache keys are sha256 hashes derived from (raw_content, provider, model,
prompt_version, schema_version, call_kind). Hits short-circuit the LLM call and
return the stored result. TTL defaults to 30 days.

Disabled when `IAC_NO_CACHE` is set (CLI flag or env var).

Stored next to the user's XDG cache dir, falling back to `~/.cache/iac-scanner/`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 30 * 24 * 3600  # 30 days
SCHEMA_VERSION = "1"  # Bump when the on-disk format changes — invalidates all entries.


def cache_root() -> Path:
    """Resolve the cache directory. XDG-compliant on Linux, `~/Library/Caches` on macOS."""
    if env_dir := os.environ.get("IAC_CACHE_DIR"):
        return Path(env_dir)
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else (Path.home() / ".cache")
    return base / "iac-scanner"


def is_disabled() -> bool:
    """Cache is skipped when IAC_NO_CACHE is truthy."""
    return bool(os.environ.get("IAC_NO_CACHE"))


@dataclass(frozen=True)
class CacheKey:
    """Inputs that uniquely identify an LLM call."""

    call_kind: str  # 'analysis' | 'fix'
    raw_content: str
    provider: str
    model: str
    prompt_version: str
    extra: str = ""  # e.g. serialized findings for the fix call

    def digest(self) -> str:
        h = hashlib.sha256()
        payload = json.dumps(
            {
                "schema": SCHEMA_VERSION,
                "call": self.call_kind,
                "provider": self.provider,
                "model": self.model,
                "prompt_version": self.prompt_version,
                "extra": self.extra,
                "content_sha": hashlib.sha256(self.raw_content.encode("utf-8")).hexdigest(),
            },
            sort_keys=True,
        ).encode("utf-8")
        h.update(payload)
        return h.hexdigest()


def _entry_path(key: CacheKey) -> Path:
    d = key.digest()
    # Shard by first two chars to keep directory listings small.
    return cache_root() / d[:2] / f"{d}.json"


def get(key: CacheKey, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> Any | None:
    """Return cached value if present and fresh; else None. Never raises."""
    if is_disabled():
        return None
    path = _entry_path(key)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("Cache read failed for %s: %s", path, e)
        return None
    stored_at = float(data.get("_stored_at", 0))
    if time.time() - stored_at > ttl_seconds:
        return None
    return data.get("value")


def put(key: CacheKey, value: Any) -> None:
    """Store value under the cache key. Never raises — cache is best-effort."""
    if is_disabled():
        return
    path = _entry_path(key)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"_stored_at": time.time(), "_digest": key.digest(), "value": value}
        path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError as e:
        logger.debug("Cache write failed for %s: %s", path, e)
