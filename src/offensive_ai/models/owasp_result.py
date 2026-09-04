"""
OWASP Top 10 2021 scan result models.

This module defines Pydantic models for representing OWASP vulnerability
scan results, findings, and categories.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class SeverityLevel(str, Enum):
    """Severity levels for OWASP findings."""
    
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScanMode(str, Enum):
    """Scanning modes for OWASP scanner."""
    
    SAFE = "safe"
    DEEP = "deep"


# Severity score mapping
SEVERITY_SCORES: Dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 15,
    SeverityLevel.HIGH: 10,
    SeverityLevel.MEDIUM: 5,
    SeverityLevel.LOW: 1,
}


class OwaspFinding(BaseModel):
    """Represents a single OWASP vulnerability finding."""
    
    category: str = Field(..., description="OWASP category (A01-A10)")
    severity: SeverityLevel = Field(..., description="Finding severity level")
    title: str = Field(..., description="Short title of the finding")
    description: str = Field(..., description="Detailed description of the issue")
    remediation_key: str = Field(..., description="Key to lookup remediation guidance")
    cwe_id: Optional[int] = Field(None, description="Common Weakness Enumeration ID")
    score: int = Field(..., description="Numeric score based on severity")
    evidence: Optional[str] = Field(None, description="Evidence or example of the finding")
    llm_reasoning: Optional[str] = Field(None, description="LLM judge reasoning for this finding")
    llm_confidence: Optional[float] = Field(None, description="LLM judge confidence score (0.0–1.0)")

    model_config = ConfigDict()

    def __init__(self, **data):
        """Initialize finding and auto-calculate score from severity."""
        if 'score' not in data and 'severity' in data:
            data['score'] = SEVERITY_SCORES[SeverityLevel(data['severity'])]
        super().__init__(**data)


class OwaspCategoryResult(BaseModel):
    """Results for a single OWASP Top 10 category."""
    
    category_id: str = Field(..., description="Category identifier (A01-A10)")
    category_name: str = Field(..., description="Human-readable category name")
    findings: List[OwaspFinding] = Field(default_factory=list, description="List of findings in this category")
    category_score: int = Field(0, description="Total score for this category")
    grade: str = Field("A", description="Letter grade for this category (A-F)")
    testable: bool = Field(True, description="Whether this category can be tested externally")
    not_testable_reason: Optional[str] = Field(None, description="Reason if not testable")

    model_config = ConfigDict()

    def calculate_score(self) -> int:
        """Calculate total score from findings."""
        self.category_score = sum(f.score for f in self.findings)
        return self.category_score
    
    def calculate_grade(self) -> str:
        """Calculate letter grade based on score."""
        self.calculate_score()
        
        if not self.testable:
            self.grade = "N/A"
        elif self.category_score == 0:
            self.grade = "A"
        elif self.category_score <= 10:
            self.grade = "B"
        elif self.category_score <= 25:
            self.grade = "C"
        elif self.category_score <= 50:
            self.grade = "D"
        else:
            self.grade = "F"
        
        return self.grade
    
    @property
    def critical_findings(self) -> List[OwaspFinding]:
        """Get all critical severity findings."""
        return [f for f in self.findings if f.severity == SeverityLevel.CRITICAL]
    
    @property
    def high_findings(self) -> List[OwaspFinding]:
        """Get all high severity findings."""
        return [f for f in self.findings if f.severity == SeverityLevel.HIGH]
    
    @property
    def has_critical(self) -> bool:
        """Check if category has any critical findings."""
        return len(self.critical_findings) > 0


class OwaspScanResult(BaseModel):
    """Complete OWASP Top 10 scan result for a target."""
    
    target: str = Field(..., description="Target URL or hostname")
    scan_mode: ScanMode = Field(..., description="Scanning mode used")
    enabled_categories: List[str] = Field(..., description="Categories that were scanned")
    overall_score: int = Field(0, description="Total vulnerability score")
    overall_grade: str = Field("A", description="Overall security grade (A-F)")
    categories: List[OwaspCategoryResult] = Field(default_factory=list, description="Results per category")
    scan_duration: float = Field(0.0, description="Scan duration in seconds")
    timestamp: datetime = Field(default_factory=datetime.now, description="Scan timestamp")

    model_config = ConfigDict()

    def calculate_overall_score(self) -> int:
        """Calculate total score from all categories."""
        self.overall_score = sum(cat.category_score for cat in self.categories)
        return self.overall_score
    
    def calculate_overall_grade(self) -> str:
        """
        Calculate overall grade based on total score.
        Automatic F grade if critical SSL/TLS (A02 crypto) failures found.
        """
        self.calculate_overall_score()
        
        # Check for critical cryptographic failures (A02) - auto F grade
        a02_category = next((cat for cat in self.categories if cat.category_id == "A02"), None)
        if a02_category and a02_category.has_critical:
            self.overall_grade = "F"
            return self.overall_grade
        
        # Calculate grade based on score thresholds
        if self.overall_score == 0:
            self.overall_grade = "A"
        elif self.overall_score <= 10:
            self.overall_grade = "B"
        elif self.overall_score <= 25:
            self.overall_grade = "C"
        elif self.overall_score <= 50:
            self.overall_grade = "D"
        else:
            self.overall_grade = "F"
        
        return self.overall_grade
    
    @property
    def all_findings(self) -> List[OwaspFinding]:
        """Get all findings across all categories."""
        findings = []
        for category in self.categories:
            findings.extend(category.findings)
        return findings
    
    @property
    def critical_findings(self) -> List[OwaspFinding]:
        """Get all critical severity findings."""
        return [f for f in self.all_findings if f.severity == SeverityLevel.CRITICAL]
    
    @property
    def high_findings(self) -> List[OwaspFinding]:
        """Get all high severity findings."""
        return [f for f in self.all_findings if f.severity == SeverityLevel.HIGH]
    
    @property
    def has_critical(self) -> bool:
        """Check if any critical findings exist."""
        return len(self.critical_findings) > 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "scan_mode": self.scan_mode.value,
            "enabled_categories": self.enabled_categories,
            "overall_score": self.overall_score,
            "overall_grade": self.overall_grade,
            "categories": [
                {
                    "category_id": cat.category_id,
                    "category_name": cat.category_name,
                    "grade": cat.grade,
                    "score": cat.category_score,
                    "testable": cat.testable,
                    "findings_count": len(cat.findings),
                    "findings": [
                        {
                            "category": f.category,
                            "severity": f.severity.value,
                            "title": f.title,
                            "description": f.description,
                            "remediation_key": f.remediation_key,
                            "cwe_id": f.cwe_id,
                            "score": f.score,
                            "evidence": f.evidence,
                        }
                        for f in cat.findings
                    ]
                }
                for cat in self.categories
            ],
            "scan_duration": self.scan_duration,
            "timestamp": self.timestamp.isoformat(),
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=2)


class BatchOwaspResult(BaseModel):
    """Batch OWASP scan results for multiple targets."""
    
    results: List[OwaspScanResult] = Field(default_factory=list, description="Individual scan results")
    total_targets: int = Field(0, description="Total number of targets scanned")
    successful_scans: int = Field(0, description="Number of successful scans")
    failed_scans: int = Field(0, description="Number of failed scans")
    scan_mode: ScanMode = Field(..., description="Scanning mode used")
    timestamp: datetime = Field(default_factory=datetime.now, description="Batch scan timestamp")

    model_config = ConfigDict()

    @property
    def vulnerable_targets(self) -> List[OwaspScanResult]:
        """Get targets with vulnerabilities (grade C or below)."""
        return [r for r in self.results if r.overall_grade in ["C", "D", "F"]]
    
    @property
    def critical_targets(self) -> List[OwaspScanResult]:
        """Get targets with critical findings."""
        return [r for r in self.results if r.has_critical]
    
    @property
    def average_grade(self) -> str:
        """Calculate average grade across all targets."""
        if not self.results:
            return "N/A"
        
        grade_values = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
        avg_value = sum(grade_values.get(r.overall_grade, 0) for r in self.results) / len(self.results)
        
        if avg_value >= 4.5:
            return "A"
        elif avg_value >= 3.5:
            return "B"
        elif avg_value >= 2.5:
            return "C"
        elif avg_value >= 1.5:
            return "D"
        else:
            return "F"
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "total_targets": self.total_targets,
            "successful_scans": self.successful_scans,
            "failed_scans": self.failed_scans,
            "scan_mode": self.scan_mode.value,
            "average_grade": self.average_grade,
            "results": [r.to_dict() for r in self.results],
            "timestamp": self.timestamp.isoformat(),
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=2)
