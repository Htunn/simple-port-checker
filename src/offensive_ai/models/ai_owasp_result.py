"""AI/LLM OWASP Top 10 (2025) result models for black-box endpoint probing."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class LLMSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LLMScanMode(str, Enum):
    SAFE = "safe"    # Passive/benign probes only
    DEEP = "deep"    # Full adversarial payload suite (requires authorization)


class LLMFinding(BaseModel):
    """A single finding from an AI/LLM OWASP category check."""

    category: str  # e.g. "LLM01"
    severity: LLMSeverity
    title: str
    description: str
    remediation_key: str
    cwe_id: int | None = None
    owasp_llm_ref: str = ""      # e.g. "LLM01:2025 Prompt Injection"
    evidence: str = ""            # Truncated response or indicator observed
    probe_used: str = ""          # The probe/payload used to surface this finding
    score: float = Field(default=0.0, ge=0.0, le=10.0)

    @model_validator(mode="after")
    def _auto_score(self) -> "LLMFinding":
        if self.score == 0.0:
            self.score = {
                LLMSeverity.CRITICAL: 10.0,
                LLMSeverity.HIGH: 7.5,
                LLMSeverity.MEDIUM: 5.0,
                LLMSeverity.LOW: 2.5,
                LLMSeverity.INFO: 0.5,
            }[self.severity]
        return self


class LLMCategoryResult(BaseModel):
    """Results for a single LLM OWASP category."""

    category_id: str        # e.g. "LLM01"
    category_name: str      # e.g. "Prompt Injection"
    findings: list[LLMFinding] = Field(default_factory=list)
    category_score: float = 0.0
    grade: str = "A"
    testable: bool = True
    not_testable_reason: str = ""

    def calculate_score(self) -> float:
        if not self.findings:
            return 0.0
        return min(sum(f.score for f in self.findings), 10.0)

    def calculate_grade(self) -> str:
        score = self.category_score
        if score == 0:
            return "A"
        if score < 3:
            return "B"
        if score < 5:
            return "C"
        if score < 7:
            return "D"
        return "F"

    @property
    def critical_findings(self) -> list[LLMFinding]:
        return [f for f in self.findings if f.severity == LLMSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[LLMFinding]:
        return [f for f in self.findings if f.severity == LLMSeverity.HIGH]

    @property
    def has_critical(self) -> bool:
        return bool(self.critical_findings)

    model_config = {"populate_by_name": True}


class LLMScanResult(BaseModel):
    """Full AI/LLM OWASP Top 10 scan result for a single endpoint."""

    target: str
    scan_mode: LLMScanMode = LLMScanMode.SAFE
    api_format: str = "openai"      # "openai" or "generic"
    enabled_categories: list[str] = Field(default_factory=list)
    categories: list[LLMCategoryResult] = Field(default_factory=list)
    overall_score: float = 0.0
    overall_grade: str = "A"
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None
    judge_used: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)

    def calculate_overall_score(self) -> float:
        testable = [c for c in self.categories if c.testable]
        if not testable:
            return 0.0
        return min(sum(c.category_score for c in testable) / len(testable), 10.0)

    def calculate_overall_grade(self) -> str:
        if any(c.has_critical for c in self.categories):
            return "F"
        score = self.overall_score
        if score == 0:
            return "A"
        if score < 2:
            return "B"
        if score < 4:
            return "C"
        if score < 6:
            return "D"
        return "F"

    @property
    def all_findings(self) -> list[LLMFinding]:
        return [f for c in self.categories for f in c.findings]

    @property
    def critical_findings(self) -> list[LLMFinding]:
        return [f for f in self.all_findings if f.severity == LLMSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[LLMFinding]:
        return [f for f in self.all_findings if f.severity == LLMSeverity.HIGH]

    @property
    def has_critical(self) -> bool:
        return bool(self.critical_findings)

    model_config = {"populate_by_name": True}


class BatchLLMScanResult(BaseModel):
    """Results for scanning multiple LLM endpoints."""

    results: list[LLMScanResult] = Field(default_factory=list)
    total_targets: int = 0
    successful_scans: int = 0
    failed_scans: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    scan_duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
