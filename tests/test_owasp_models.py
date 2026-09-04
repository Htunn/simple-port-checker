"""Tests for OWASP result models (no network required)."""

from __future__ import annotations

import json

import pytest

from offensive_ai.models.owasp_result import (
    BatchOwaspResult,
    OwaspCategoryResult,
    OwaspFinding,
    OwaspScanResult,
    ScanMode,
    SEVERITY_SCORES,
    SeverityLevel,
)


# ---------------------------------------------------------------------------
# SeverityLevel + SEVERITY_SCORES
# ---------------------------------------------------------------------------

class TestSeverityScores:
    def test_critical_score(self):
        assert SEVERITY_SCORES[SeverityLevel.CRITICAL] == 15

    def test_high_score(self):
        assert SEVERITY_SCORES[SeverityLevel.HIGH] == 10

    def test_medium_score(self):
        assert SEVERITY_SCORES[SeverityLevel.MEDIUM] == 5

    def test_low_score(self):
        assert SEVERITY_SCORES[SeverityLevel.LOW] == 1


# ---------------------------------------------------------------------------
# OwaspFinding
# ---------------------------------------------------------------------------

class TestOwaspFinding:
    def _make(self, severity=SeverityLevel.HIGH, score=None):
        kwargs = dict(
            category="A02",
            severity=severity,
            title="Missing HSTS",
            description="HSTS header is absent",
            remediation_key="missing_hsts",
        )
        if score is not None:
            kwargs["score"] = score
        return OwaspFinding(**kwargs)

    def test_score_auto_calculated_from_severity(self):
        finding = self._make(severity=SeverityLevel.CRITICAL)
        assert finding.score == 15

    def test_score_from_medium(self):
        finding = self._make(severity=SeverityLevel.MEDIUM)
        assert finding.score == 5

    def test_explicit_score_used(self):
        finding = self._make(score=99)
        assert finding.score == 99

    def test_optional_fields_default_none(self):
        finding = self._make()
        assert finding.cwe_id is None
        assert finding.evidence is None
        assert finding.llm_reasoning is None
        assert finding.llm_confidence is None

    def test_with_evidence(self):
        finding = OwaspFinding(
            category="A05",
            severity=SeverityLevel.MEDIUM,
            title="Debug mode",
            description="Application runs in debug mode",
            remediation_key="debug_mode",
            score=5,
            evidence="X-Debug-Token header present",
        )
        assert finding.evidence == "X-Debug-Token header present"

    def test_cwe_id_stored(self):
        finding = OwaspFinding(
            category="A07",
            severity=SeverityLevel.HIGH,
            title="Weak auth",
            description="Weak auth detected",
            remediation_key="weak_auth",
            score=10,
            cwe_id=307,
        )
        assert finding.cwe_id == 307


# ---------------------------------------------------------------------------
# OwaspCategoryResult
# ---------------------------------------------------------------------------

class TestOwaspCategoryResult:
    def _make_category(self, findings=None, testable=True):
        return OwaspCategoryResult(
            category_id="A02",
            category_name="Cryptographic Failures",
            findings=findings or [],
            testable=testable,
        )

    def _critical_finding(self):
        return OwaspFinding(
            category="A02", severity=SeverityLevel.CRITICAL,
            title="No TLS", description="No TLS detected",
            remediation_key="no_tls", score=15,
        )

    def _high_finding(self):
        return OwaspFinding(
            category="A02", severity=SeverityLevel.HIGH,
            title="Weak cipher", description="Weak cipher used",
            remediation_key="weak_cipher", score=10,
        )

    def _medium_finding(self):
        return OwaspFinding(
            category="A02", severity=SeverityLevel.MEDIUM,
            title="Missing HSTS", description="HSTS absent",
            remediation_key="missing_hsts", score=5,
        )

    def test_calculate_score_empty(self):
        cat = self._make_category(findings=[])
        assert cat.calculate_score() == 0

    def test_calculate_score_sum(self):
        cat = self._make_category(findings=[self._critical_finding(), self._high_finding()])
        assert cat.calculate_score() == 25

    def test_grade_a_no_findings(self):
        cat = self._make_category(findings=[])
        cat.calculate_grade()
        assert cat.grade == "A"

    def test_grade_b_low_score(self):
        cat = self._make_category(findings=[self._medium_finding()])
        cat.calculate_grade()
        assert cat.grade in ("A", "B")  # score=5, B threshold is <=10

    def test_grade_c_medium_score(self):
        # score=25 → grade C
        cat = self._make_category(findings=[self._critical_finding(), self._high_finding()])
        cat.calculate_grade()
        assert cat.grade == "C"

    def test_grade_f_high_score(self):
        # score > 50 → grade F
        findings = [self._critical_finding()] * 5  # 5 * 15 = 75
        cat = self._make_category(findings=findings)
        cat.calculate_grade()
        assert cat.grade == "F"

    def test_grade_na_not_testable(self):
        cat = self._make_category(testable=False)
        cat.calculate_grade()
        assert cat.grade == "N/A"

    def test_critical_findings_property(self):
        cat = self._make_category(findings=[self._critical_finding(), self._high_finding()])
        assert len(cat.critical_findings) == 1
        assert cat.critical_findings[0].severity == SeverityLevel.CRITICAL

    def test_high_findings_property(self):
        cat = self._make_category(findings=[self._critical_finding(), self._high_finding()])
        assert len(cat.high_findings) == 1

    def test_has_critical_true(self):
        cat = self._make_category(findings=[self._critical_finding()])
        assert cat.has_critical is True

    def test_has_critical_false(self):
        cat = self._make_category(findings=[self._high_finding()])
        assert cat.has_critical is False


# ---------------------------------------------------------------------------
# OwaspScanResult
# ---------------------------------------------------------------------------

class TestOwaspScanResult:
    def _make_result(self, categories=None, scan_mode=ScanMode.SAFE):
        return OwaspScanResult(
            target="https://example.com",
            scan_mode=scan_mode,
            enabled_categories=["A02", "A05"],
            categories=categories or [],
        )

    def _make_cat(self, cat_id, findings=None):
        c = OwaspCategoryResult(
            category_id=cat_id,
            category_name=f"Category {cat_id}",
            findings=findings or [],
        )
        c.calculate_grade()
        return c

    def _critical_finding(self, cat_id="A02"):
        return OwaspFinding(
            category=cat_id, severity=SeverityLevel.CRITICAL,
            title="Critical", description="Critical issue",
            remediation_key="test", score=15,
        )

    def test_all_findings_aggregated(self):
        f1 = self._critical_finding("A02")
        f2 = OwaspFinding(
            category="A05", severity=SeverityLevel.HIGH,
            title="H", description="H", remediation_key="t", score=10,
        )
        cat1 = self._make_cat("A02", [f1])
        cat2 = self._make_cat("A05", [f2])
        result = self._make_result(categories=[cat1, cat2])
        assert len(result.all_findings) == 2

    def test_all_findings_empty(self):
        result = self._make_result(categories=[])
        assert result.all_findings == []

    def test_critical_findings_property(self):
        f_crit = self._critical_finding()
        cat = self._make_cat("A02", [f_crit])
        result = self._make_result(categories=[cat])
        assert len(result.critical_findings) == 1

    def test_has_critical_true(self):
        f = self._critical_finding()
        cat = self._make_cat("A02", [f])
        result = self._make_result(categories=[cat])
        assert result.has_critical is True

    def test_has_critical_false(self):
        result = self._make_result(categories=[])
        assert result.has_critical is False

    def test_calculate_overall_score(self):
        f1 = self._critical_finding("A02")  # score=15
        f2 = OwaspFinding(
            category="A05", severity=SeverityLevel.HIGH,
            title="H", description="H", remediation_key="t", score=10,
        )
        cat1 = self._make_cat("A02", [f1])
        cat2 = self._make_cat("A05", [f2])
        result = self._make_result(categories=[cat1, cat2])
        assert result.calculate_overall_score() == 25

    def test_overall_grade_a_no_findings(self):
        result = self._make_result(categories=[self._make_cat("A02", [])])
        result.calculate_overall_grade()
        assert result.overall_grade == "A"

    def test_overall_grade_f_critical_a02(self):
        """A02 with critical findings forces grade F."""
        f = self._critical_finding("A02")
        cat = self._make_cat("A02", [f])
        result = self._make_result(categories=[cat])
        result.calculate_overall_grade()
        assert result.overall_grade == "F"

    def test_overall_grade_b(self):
        """Total score <= 10 but no A02 critical → grade B."""
        f = OwaspFinding(
            category="A05", severity=SeverityLevel.HIGH,
            title="H", description="H", remediation_key="t", score=10,
        )
        cat = self._make_cat("A05", [f])
        result = self._make_result(categories=[cat])
        result.calculate_overall_grade()
        assert result.overall_grade == "B"

    def test_overall_grade_d(self):
        """Score in range 26-50 → D."""
        findings = [
            OwaspFinding(
                category="A05", severity=SeverityLevel.HIGH,
                title=f"H{i}", description="H", remediation_key="t", score=10,
            )
            for i in range(4)  # 40 total
        ]
        cat = self._make_cat("A05", findings)
        result = self._make_result(categories=[cat])
        result.calculate_overall_grade()
        assert result.overall_grade == "D"

    def test_to_dict_keys(self):
        result = self._make_result()
        d = result.to_dict()
        for key in ("target", "scan_mode", "overall_score", "overall_grade", "categories", "scan_duration"):
            assert key in d

    def test_to_dict_scan_mode_value(self):
        result = self._make_result(scan_mode=ScanMode.DEEP)
        d = result.to_dict()
        assert d["scan_mode"] == "deep"

    def test_to_json_valid(self):
        result = self._make_result()
        result.calculate_overall_grade()
        parsed = json.loads(result.to_json())
        assert parsed["target"] == "https://example.com"

    def test_to_json_round_trip(self):
        f = self._critical_finding()
        cat = self._make_cat("A02", [f])
        result = self._make_result(categories=[cat])
        result.calculate_overall_grade()
        d = json.loads(result.to_json())
        assert len(d["categories"]) == 1
        assert len(d["categories"][0]["findings"]) == 1


# ---------------------------------------------------------------------------
# BatchOwaspResult
# ---------------------------------------------------------------------------

class TestBatchOwaspResult:
    def _make_scan(self, grade, has_crit=False):
        r = OwaspScanResult(
            target=f"https://{grade.lower()}.example.com",
            scan_mode=ScanMode.SAFE,
            enabled_categories=["A02"],
            categories=[],
        )
        r.overall_grade = grade
        if has_crit:
            f = OwaspFinding(
                category="A02", severity=SeverityLevel.CRITICAL,
                title="C", description="C", remediation_key="t", score=15,
            )
            r.categories.append(OwaspCategoryResult(
                category_id="A02", category_name="Crypto", findings=[f]
            ))
        return r

    def _make_batch(self):
        return BatchOwaspResult(
            results=[
                self._make_scan("A"),
                self._make_scan("C"),
                self._make_scan("F", has_crit=True),
            ],
            total_targets=3,
            successful_scans=3,
            failed_scans=0,
            scan_mode=ScanMode.SAFE,
        )

    def test_vulnerable_targets(self):
        batch = self._make_batch()
        vuln = batch.vulnerable_targets
        grades = {r.overall_grade for r in vuln}
        assert "C" in grades or "F" in grades
        assert "A" not in grades

    def test_critical_targets(self):
        batch = self._make_batch()
        crit = batch.critical_targets
        assert len(crit) == 1
        assert crit[0].has_critical is True

    def test_average_grade_empty(self):
        batch = BatchOwaspResult(
            results=[],
            total_targets=0,
            successful_scans=0,
            failed_scans=0,
            scan_mode=ScanMode.SAFE,
        )
        assert batch.average_grade == "N/A"

    def test_average_grade_all_a(self):
        batch = BatchOwaspResult(
            results=[self._make_scan("A"), self._make_scan("A")],
            total_targets=2,
            successful_scans=2,
            failed_scans=0,
            scan_mode=ScanMode.SAFE,
        )
        assert batch.average_grade == "A"

    def test_average_grade_mixed(self):
        batch = self._make_batch()
        # A(5) + C(3) + F(1) = 9 / 3 = 3.0 → grade C
        assert batch.average_grade == "C"

    def test_to_dict_keys(self):
        batch = self._make_batch()
        d = batch.to_dict()
        for key in ("total_targets", "successful_scans", "failed_scans", "scan_mode", "results"):
            assert key in d

    def test_to_json_valid(self):
        batch = self._make_batch()
        parsed = json.loads(batch.to_json())
        assert parsed["total_targets"] == 3
