"""
Tests for exporters — CSV, JSON, and PDF generation from OWASP scan results.
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from offensive_ai.models.owasp_result import (
    OwaspCategoryResult,
    OwaspFinding,
    OwaspScanResult,
    ScanMode,
    SeverityLevel,
)
from offensive_ai.utils.exporters import (
    OwaspPdfExporter,
    export_to_csv,
    export_to_json,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(
    category="A01",
    severity=SeverityLevel.HIGH,
    title="Test Finding",
    description="A test vulnerability",
    remediation_key="cors_misconfiguration",
    cwe_id=79,
    evidence="test evidence",
):
    return OwaspFinding(
        category=category,
        severity=severity,
        title=title,
        description=description,
        remediation_key=remediation_key,
        cwe_id=cwe_id,
        evidence=evidence,
    )


def make_category_result(
    category_id="A01",
    category_name="Broken Access Control",
    findings=None,
):
    cat = OwaspCategoryResult(
        category_id=category_id,
        category_name=category_name,
        findings=findings or [],
    )
    cat.calculate_grade()
    return cat


def make_scan_result(with_findings=True):
    findings = [
        make_finding(severity=SeverityLevel.CRITICAL, title="Critical Issue"),
        make_finding(severity=SeverityLevel.HIGH, title="High Issue"),
        make_finding(severity=SeverityLevel.MEDIUM, title="Medium Issue"),
    ] if with_findings else []

    cat = make_category_result(findings=findings)

    result = OwaspScanResult(
        target="https://example.com",
        scan_mode=ScanMode.SAFE,
        enabled_categories=["A01"],
        categories=[cat],
        scan_duration=1.5,
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
    )
    result.calculate_overall_grade()
    return result


# ---------------------------------------------------------------------------
# CSV export tests
# ---------------------------------------------------------------------------

class TestExportToCsv:
    def test_creates_csv_file(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            filepath = f.name
        try:
            export_to_csv(result, filepath)
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_csv_has_header_row(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            filepath = f.name
        try:
            export_to_csv(result, filepath)
            with open(filepath, newline="", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                assert "Category ID" in reader.fieldnames
                assert "Severity" in reader.fieldnames
                assert "Title" in reader.fieldnames
        finally:
            os.unlink(filepath)

    def test_csv_contains_finding_data(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            filepath = f.name
        try:
            export_to_csv(result, filepath)
            with open(filepath, newline="", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
            assert len(rows) == 3  # 3 findings
        finally:
            os.unlink(filepath)

    def test_csv_severity_values(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            filepath = f.name
        try:
            export_to_csv(result, filepath)
            with open(filepath, newline="", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
            severities = {row["Severity"] for row in rows}
            assert "CRITICAL" in severities
            assert "HIGH" in severities
        finally:
            os.unlink(filepath)

    def test_csv_empty_findings(self):
        result = make_scan_result(with_findings=False)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            filepath = f.name
        try:
            export_to_csv(result, filepath)
            with open(filepath, newline="", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
            assert rows == []
        finally:
            os.unlink(filepath)

    def test_csv_cwe_id_present(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            filepath = f.name
        try:
            export_to_csv(result, filepath)
            with open(filepath, newline="", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
            cwe_ids = [row["CWE ID"] for row in rows if row["CWE ID"]]
            assert len(cwe_ids) > 0
        finally:
            os.unlink(filepath)


# ---------------------------------------------------------------------------
# JSON export tests
# ---------------------------------------------------------------------------

class TestExportToJson:
    def test_creates_json_file(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name
        try:
            export_to_json(result, filepath)
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_json_is_valid(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name
        try:
            export_to_json(result, filepath)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            assert isinstance(data, dict)
        finally:
            os.unlink(filepath)

    def test_json_contains_target(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name
        try:
            export_to_json(result, filepath)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            assert data["target"] == "https://example.com"
        finally:
            os.unlink(filepath)

    def test_json_contains_categories(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name
        try:
            export_to_json(result, filepath)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            assert "categories" in data
            assert len(data["categories"]) > 0
        finally:
            os.unlink(filepath)

    def test_json_with_remediation(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name
        try:
            export_to_json(result, filepath, include_remediation=True)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            assert isinstance(data, dict)
            # File should be larger than without remediation
            size_with = os.path.getsize(filepath)
            assert size_with > 0
        finally:
            os.unlink(filepath)

    def test_json_without_remediation(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name
        try:
            export_to_json(result, filepath, include_remediation=False)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            # Categories should not have 'remediation' injected
            for category in data.get("categories", []):
                for finding in category.get("findings", []):
                    assert "remediation" not in finding
        finally:
            os.unlink(filepath)

    def test_json_with_tech_stack(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name
        try:
            export_to_json(result, filepath, include_remediation=True, tech_stack="python")
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            assert isinstance(data, dict)
        finally:
            os.unlink(filepath)

    def test_json_overall_grade_present(self):
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filepath = f.name
        try:
            export_to_json(result, filepath)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            assert "overall_grade" in data
        finally:
            os.unlink(filepath)


# ---------------------------------------------------------------------------
# PDF export tests
# ---------------------------------------------------------------------------

class TestOwaspPdfExporter:
    def test_init_default(self):
        exporter = OwaspPdfExporter()
        assert exporter.tech_stack == "generic"

    def test_init_custom_tech_stack(self):
        exporter = OwaspPdfExporter(tech_stack="python")
        assert exporter.tech_stack == "python"

    def test_styles_setup(self):
        exporter = OwaspPdfExporter()
        assert "CustomTitle" in exporter.styles

    def test_get_grade_color_a(self):
        exporter = OwaspPdfExporter()
        assert "#27ae60" in exporter._get_grade_color("A")

    def test_get_grade_color_f(self):
        exporter = OwaspPdfExporter()
        assert "#e74c3c" in exporter._get_grade_color("F")

    def test_get_grade_color_unknown(self):
        exporter = OwaspPdfExporter()
        result = exporter._get_grade_color("Z")
        assert isinstance(result, str)

    def test_get_severity_color_critical(self):
        exporter = OwaspPdfExporter()
        color = exporter._get_severity_color(SeverityLevel.CRITICAL)
        assert color.startswith("#")

    def test_get_severity_color_high(self):
        exporter = OwaspPdfExporter()
        color = exporter._get_severity_color(SeverityLevel.HIGH)
        assert "#e74c3c" in color

    def test_export_creates_pdf(self):
        exporter = OwaspPdfExporter()
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            filepath = f.name
        try:
            exporter.export(result, filepath)
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_export_pdf_is_valid_pdf_header(self):
        exporter = OwaspPdfExporter()
        result = make_scan_result()
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            filepath = f.name
        try:
            exporter.export(result, filepath)
            with open(filepath, "rb") as f:
                header = f.read(4)
            assert header == b"%PDF"
        finally:
            os.unlink(filepath)

    def test_export_empty_findings_pdf(self):
        exporter = OwaspPdfExporter()
        result = make_scan_result(with_findings=False)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            filepath = f.name
        try:
            exporter.export(result, filepath)
            assert os.path.exists(filepath)
        finally:
            os.unlink(filepath)

    def test_create_cover_page_returns_list(self):
        exporter = OwaspPdfExporter()
        result = make_scan_result()
        elements = exporter._create_cover_page(result)
        assert isinstance(elements, list)
        assert len(elements) > 0

    def test_create_executive_summary_returns_list(self):
        exporter = OwaspPdfExporter()
        result = make_scan_result()
        elements = exporter._create_executive_summary(result)
        assert isinstance(elements, list)
        assert len(elements) > 0

    def test_create_appendix_returns_list(self):
        exporter = OwaspPdfExporter()
        elements = exporter._create_appendix()
        assert isinstance(elements, list)
        assert len(elements) > 0
