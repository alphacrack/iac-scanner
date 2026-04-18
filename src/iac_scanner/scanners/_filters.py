"""Shared input-safety filters for all scanners.

Three concerns, all applied before raw IaC content is sent to an LLM:

1. **Skip-list** — files we refuse to read at all (state files, `.env`, `.tfvars`,
   lock files). These are the highest-risk secret carriers in a typical IaC repo.

2. **Secret redaction** — obvious secret patterns are masked inline so a forgotten
   AWS key in a `main.tf` comment doesn't get shipped to OpenAI.

3. **Input size cap** — a hard limit on total raw content. Protects against:
     (a) accidentally scanning a multi-MB module (runaway cost),
     (b) prompt-injection attacks that try to stuff the context to override
         the system prompt.

All three are configurable via env vars for escape hatches, with safe defaults.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# ---- Skip-list -------------------------------------------------------------

DEFAULT_SKIP_PATTERNS: tuple[str, ...] = (
    # Terraform state — often contains plaintext secrets
    "terraform.tfstate",
    "terraform.tfstate.backup",
    "*.tfstate",
    "*.tfstate.backup",
    # Terraform variable files — conventionally hold secrets
    "*.tfvars",
    "*.auto.tfvars",
    "*.tfvars.json",
    # Dotenv / secrets files
    ".env",
    ".env.*",
    "*.env",
    "secrets.*",
    "*.secrets.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_rsa.*",
    "id_ed25519",
    "id_ed25519.*",
    # Lock / vendor dirs — large, not IaC source
    ".terraform.lock.hcl",
    "node_modules",
    "cdk.out",
    ".terraform",
    "venv",
    ".venv",
    "__pycache__",
    "*.pyc",
    # Cloud provider credentials
    "credentials",
    "config",
)


def should_skip(path: Path, patterns: tuple[str, ...] = DEFAULT_SKIP_PATTERNS) -> bool:
    """True if this file or any parent directory matches a skip pattern."""
    name = path.name
    for pattern in patterns:
        if fnmatch.fnmatch(name, pattern):
            return True
    # Also skip if any ancestor directory is in the list (node_modules, .venv, etc.)
    for part in path.parts:
        for pattern in patterns:
            if fnmatch.fnmatch(part, pattern):
                return True
    return False


# ---- Secret redaction ------------------------------------------------------

_REDACTED = "<REDACTED_SECRET>"

# Order matters: apply longer/more-specific patterns first so generic heuristics
# don't eat credentials that have a known shape.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # AWS access key IDs
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), _REDACTED),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), _REDACTED),
    # AWS secret access keys (assignment form only — avoid false positives on random base64)
    (
        re.compile(
            r"""(aws_secret_access_key|secret_access_key|secret_key)\s*=\s*["'][^"'\s]{30,}["']""", re.IGNORECASE
        ),
        rf'\1 = "{_REDACTED}"',
    ),
    # GitHub tokens
    (re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"), _REDACTED),
    (re.compile(r"\bgho_[A-Za-z0-9]{36,}\b"), _REDACTED),
    (re.compile(r"\bghu_[A-Za-z0-9]{36,}\b"), _REDACTED),
    (re.compile(r"\bghs_[A-Za-z0-9]{36,}\b"), _REDACTED),
    (re.compile(r"\bghr_[A-Za-z0-9]{36,}\b"), _REDACTED),
    # OpenAI keys
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), _REDACTED),
    # Anthropic keys
    (re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), _REDACTED),
    # Slack bot / user tokens
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), _REDACTED),
    # Generic Bearer tokens
    (re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{20,}"), f"Bearer {_REDACTED}"),
    # PEM-enclosed private keys (multi-line)
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
            r"[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
        ),
        f"-----BEGIN PRIVATE KEY-----\n{_REDACTED}\n-----END PRIVATE KEY-----",
    ),
    # JWT-looking tokens (three base64url segments)
    (re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"), _REDACTED),
)


def redact_secrets(text: str) -> str:
    """Return `text` with common secret patterns masked inline. Best-effort."""
    if os.environ.get("IAC_NO_REDACT"):
        return text
    redacted = text
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


# ---- Input size cap --------------------------------------------------------

DEFAULT_MAX_INPUT_BYTES = 200 * 1024  # 200 KB


class InputTooLargeError(RuntimeError):
    """Raised when aggregate scanner content exceeds the configured cap."""


def max_input_bytes() -> int:
    """Configurable via IAC_MAX_INPUT_BYTES. Minimum 1KB, maximum 10MB."""
    raw = os.environ.get("IAC_MAX_INPUT_BYTES")
    if raw is None:
        return DEFAULT_MAX_INPUT_BYTES
    try:
        val = int(raw)
    except ValueError:
        logger.warning("Invalid IAC_MAX_INPUT_BYTES=%r; using default", raw)
        return DEFAULT_MAX_INPUT_BYTES
    return max(1024, min(val, 10 * 1024 * 1024))


def enforce_input_size(content: str) -> None:
    """Raise InputTooLargeError if content exceeds the cap."""
    size = len(content.encode("utf-8"))
    cap = max_input_bytes()
    if size > cap:
        raise InputTooLargeError(
            f"Input size {size:,} bytes exceeds cap {cap:,} bytes "
            f"(IAC_MAX_INPUT_BYTES). Reduce the scan scope, split the module, "
            f"or raise the cap explicitly."
        )
