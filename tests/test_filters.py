"""Unit tests for scanners/_filters.py — skip-list, secret redaction, size cap."""

from __future__ import annotations

from pathlib import Path

import pytest

from iac_scanner.scanners._filters import (
    DEFAULT_MAX_INPUT_BYTES,
    InputTooLargeError,
    enforce_input_size,
    max_input_bytes,
    redact_secrets,
    should_skip,
)


class TestShouldSkip:
    @pytest.mark.parametrize(
        "path",
        [
            "terraform.tfstate",
            "terraform.tfstate.backup",
            "my-module.tfstate",
            "prod.tfvars",
            "shared.auto.tfvars",
            ".env",
            ".env.local",
            "secrets.json",
            "prod.secrets.yaml",
            "private.pem",
            "deploy.key",
            "id_rsa",
            "id_rsa.pub",
            ".terraform.lock.hcl",
        ],
    )
    def test_skips_secret_bearing_files(self, path: str) -> None:
        assert should_skip(Path(path)) is True

    @pytest.mark.parametrize(
        "path",
        [
            "main.tf",
            "variables.tf",
            "index.ts",
            "lib/stack.ts",
            "bin/app.ts",
        ],
    )
    def test_does_not_skip_iac_source_files(self, path: str) -> None:
        assert should_skip(Path(path)) is False

    @pytest.mark.parametrize(
        "path",
        [
            "node_modules/pkg/index.js",
            "cdk.out/assets/main.ts",
            ".terraform/modules/foo/main.tf",
            ".venv/site-packages/thing.tf",
        ],
    )
    def test_skips_files_under_skip_list_directories(self, path: str) -> None:
        assert should_skip(Path(path)) is True


class TestRedactSecrets:
    def test_redacts_aws_access_key(self) -> None:
        raw = 'aws_access_key = "AKIAIOSFODNN7EXAMPLE"'
        out = redact_secrets(raw)
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert "REDACTED_SECRET" in out

    def test_redacts_github_token(self) -> None:
        raw = "# token ghp_abcdefghijklmnopqrstuvwxyz0123456789 in comments"
        out = redact_secrets(raw)
        assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in out

    def test_redacts_openai_key(self) -> None:
        raw = 'OPENAI_KEY = "sk-abcdef1234567890abcdef1234567890"'
        out = redact_secrets(raw)
        assert "sk-abcdef1234567890abcdef1234567890" not in out

    def test_redacts_anthropic_key(self) -> None:
        raw = "claude_key = sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        out = redact_secrets(raw)
        assert "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" not in out

    def test_redacts_bearer_token(self) -> None:
        raw = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123"
        out = redact_secrets(raw)
        assert "Bearer <REDACTED_SECRET>" in out

    def test_redacts_private_key_block(self) -> None:
        raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAzV8lhIK...\n-----END RSA PRIVATE KEY-----"
        out = redact_secrets(raw)
        assert "MIIEowIBAAKCAQEAzV8lhIK" not in out
        assert "REDACTED_SECRET" in out

    def test_redacts_jwt_token(self) -> None:
        raw = "auth = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefg"
        out = redact_secrets(raw)
        assert "eyJhbGciOiJIUzI1NiJ9" not in out

    def test_redact_is_idempotent(self) -> None:
        raw = 'key = "AKIAIOSFODNN7EXAMPLE"'
        once = redact_secrets(raw)
        twice = redact_secrets(once)
        assert once == twice

    def test_can_be_disabled_via_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAC_NO_REDACT", "1")
        raw = 'key = "AKIAIOSFODNN7EXAMPLE"'
        assert redact_secrets(raw) == raw


class TestInputSizeCap:
    def test_default_cap_is_200kb(self) -> None:
        assert max_input_bytes() == DEFAULT_MAX_INPUT_BYTES
        assert DEFAULT_MAX_INPUT_BYTES == 200 * 1024

    def test_cap_is_configurable_via_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAC_MAX_INPUT_BYTES", "50000")
        assert max_input_bytes() == 50000

    def test_cap_has_floor_and_ceiling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Below 1KB floors to 1KB
        monkeypatch.setenv("IAC_MAX_INPUT_BYTES", "100")
        assert max_input_bytes() == 1024
        # Above 10MB ceilings to 10MB
        monkeypatch.setenv("IAC_MAX_INPUT_BYTES", str(100 * 1024 * 1024))
        assert max_input_bytes() == 10 * 1024 * 1024

    def test_invalid_env_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAC_MAX_INPUT_BYTES", "not-a-number")
        assert max_input_bytes() == DEFAULT_MAX_INPUT_BYTES

    def test_enforce_accepts_small_input(self) -> None:
        enforce_input_size("hello" * 100)  # does not raise

    def test_enforce_raises_on_oversize(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("IAC_MAX_INPUT_BYTES", "1024")
        with pytest.raises(InputTooLargeError):
            enforce_input_size("a" * 2000)
