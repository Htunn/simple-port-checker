"""
Shared LLM provider auto-detection, used by ``LLMJudge`` and the agentic REPL.

Provider priority when multiple API keys are set: Gemini > Anthropic > OpenAI.
"""

from __future__ import annotations

import os


def detect_provider() -> str | None:
    """Auto-detect an LLM provider from environment variables.

    Returns "gemini", "anthropic", "openai", or None if nothing is configured.
    """
    if os.getenv("GEMINI_API_KEY"):
        return "gemini"
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.getenv("OPENAI_API_KEY") or os.getenv("OFFENSIVE_AI_LLM_BASE_URL"):
        return "openai"
    return None


def default_model(provider: str | None) -> str:
    """Return the default model name for *provider* (empty string if None)."""
    if provider == "openai":
        return os.getenv("OFFENSIVE_AI_LLM_MODEL", "gpt-4o-mini")
    if provider == "anthropic":
        return os.getenv("OFFENSIVE_AI_LLM_MODEL", "claude-3-haiku-20240307")
    if provider == "gemini":
        # gemini-1.5-flash was retired by Google (404s as of 2026); 2.5-flash is
        # the newest alias confirmed to support tool calling via the legacy SDK.
        return os.getenv("OFFENSIVE_AI_LLM_MODEL", "gemini-2.5-flash")
    return ""
