"""
Pydantic v2 result models for the LLM active attack modules.

These models are used by ``LLMConversationAttacker`` and the upcoming
``offensive-ai llm-attack`` CLI command.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class LLMAttackSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LLMAttackResult(BaseModel):
    """Result of a single attack probe against an LLM endpoint."""

    attack_id: str
    pattern: str           # jailbreak | encoding | multiturn | agentic | guardrail
    technique: str = ""    # specific technique or encoding method
    owasp_refs: list[str] = Field(default_factory=list)
    severity: LLMAttackSeverity = LLMAttackSeverity.HIGH
    succeeded: bool = False
    evidence: str = ""
    probe_sent: str = ""   # prompt or encoded payload (truncated)
    response_excerpt: str = ""
    http_status: int = 0
    duration: float = 0.0
    error: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class LLMAttackReport(BaseModel):
    """Aggregated report for an llm-attack run."""

    target: str
    endpoint: str
    mode: str = "safe"                # safe | deep
    patterns_run: list[str] = Field(default_factory=list)
    attack_results: list[LLMAttackResult] = Field(default_factory=list)
    guardrail_grade: str = ""         # A-F, populated by guardrail bench
    attack_duration: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: str = ""
    authorized: bool = True

    @property
    def successful_attacks(self) -> list[LLMAttackResult]:
        return [r for r in self.attack_results if r.succeeded]

    @property
    def critical_successes(self) -> list[LLMAttackResult]:
        return [
            r for r in self.attack_results
            if r.succeeded and r.severity == LLMAttackSeverity.CRITICAL
        ]

    @property
    def success_rate(self) -> float:
        if not self.attack_results:
            return 0.0
        return len(self.successful_attacks) / len(self.attack_results)
