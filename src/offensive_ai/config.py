"""
offensive-ai centralised configuration via pydantic-settings.

Configuration is loaded from environment variables (optionally via a ``.env``
file) and validated at import time.  Call ``get_config()`` to obtain the
singleton; call ``reset_config()`` in tests to reinitialise from a fresh
environment.

Sensitive values (API keys) are stored as ``pydantic.SecretStr`` and will
*not* be serialised or printed as plain text.

Environment variables
---------------------
Standard provider keys (no prefix required):

- ``OPENAI_API_KEY``
- ``ANTHROPIC_API_KEY``
- ``GEMINI_API_KEY``

offensive-ai-specific keys (``OFFENSIVE_AI_`` prefix):

- ``OFFENSIVE_AI_LLM_BASE_URL``   — custom OpenAI-compatible base URL
- ``OFFENSIVE_AI_LLM_MODEL``      — model name override
- ``OFFENSIVE_AI_DEFAULT_TIMEOUT``  — per-request timeout (default 15.0 s)
- ``OFFENSIVE_AI_DEFAULT_CONCURRENT`` — max concurrent requests (default 50)
- ``OFFENSIVE_AI_MAX_RETRIES``    — retry count (default 3)
- ``OFFENSIVE_AI_RETRY_DELAY``    — base retry delay in seconds (default 1.0)
- ``OFFENSIVE_AI_LOG_LEVEL``      — logging level: DEBUG/INFO/WARNING/ERROR/CRITICAL
- ``OFFENSIVE_AI_LOG_FORMAT``     — ``text`` (default) or ``json``
- ``OFFENSIVE_AI_AUDIT_LOG_FILE`` — path for rotating audit log (attack operations)
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class OffensiveAIConfig(BaseSettings):
    """Validated runtime configuration for the offensive-ai package."""

    model_config = SettingsConfigDict(
        env_prefix="OFFENSIVE_AI_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    # ------------------------------------------------------------------
    # LLM provider credentials (standard env var names — no OFFENSIVE_AI_ prefix)
    # ------------------------------------------------------------------
    openai_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("OPENAI_API_KEY", "OFFENSIVE_AI_OPENAI_API_KEY"),
    )
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("ANTHROPIC_API_KEY", "OFFENSIVE_AI_ANTHROPIC_API_KEY"),
    )
    gemini_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("GEMINI_API_KEY", "OFFENSIVE_AI_GEMINI_API_KEY"),
    )

    # Custom OpenAI-compatible endpoint / model
    llm_base_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("OFFENSIVE_AI_LLM_BASE_URL", "LLM_BASE_URL"),
    )
    llm_model: str | None = Field(
        default=None,
        validation_alias=AliasChoices("OFFENSIVE_AI_LLM_MODEL", "LLM_MODEL"),
    )

    # ------------------------------------------------------------------
    # Scanner defaults
    # ------------------------------------------------------------------
    default_timeout: float = Field(default=15.0, gt=0)
    default_concurrent: int = Field(default=50, ge=1, le=500)
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_delay: float = Field(default=1.0, ge=0)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "WARNING"
    log_format: Literal["text", "json"] = "text"
    audit_log_file: str | None = None

    # ------------------------------------------------------------------
    # Convenience helpers (never serialise raw key material)
    # ------------------------------------------------------------------

    def has_openai(self) -> bool:
        """Return True if an OpenAI API key is configured."""
        return self.openai_api_key is not None

    def has_anthropic(self) -> bool:
        """Return True if an Anthropic API key is configured."""
        return self.anthropic_api_key is not None

    def has_gemini(self) -> bool:
        """Return True if a Gemini API key is configured."""
        return self.gemini_api_key is not None

    def has_any_llm_key(self) -> bool:
        """Return True if any LLM provider key is configured."""
        return self.has_openai() or self.has_anthropic() or self.has_gemini()

    def openai_key_value(self) -> str | None:
        """Return the OpenAI key as plain text (use only where required by SDK)."""
        return self.openai_api_key.get_secret_value() if self.openai_api_key else None

    def anthropic_key_value(self) -> str | None:
        """Return the Anthropic key as plain text (use only where required by SDK)."""
        return self.anthropic_api_key.get_secret_value() if self.anthropic_api_key else None

    def gemini_key_value(self) -> str | None:
        """Return the Gemini key as plain text (use only where required by SDK)."""
        return self.gemini_api_key.get_secret_value() if self.gemini_api_key else None


@lru_cache(maxsize=1)
def get_config() -> OffensiveAIConfig:
    """Return the process-wide ``OffensiveAIConfig`` singleton (cached after first call)."""
    return OffensiveAIConfig()


def reset_config() -> None:
    """Clear the cached config singleton (useful in tests)."""
    get_config.cache_clear()
