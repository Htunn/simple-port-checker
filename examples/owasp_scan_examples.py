"""
Example usage of OWASP Top 10 2021 security scanner.

This module demonstrates various ways to use the OWASP scanner
programmatically in your Python applications.
"""

import asyncio
from pathlib import Path

from offensive_ai import OwaspScanner
from offensive_ai.models.owasp_result import SeverityLevel
from offensive_ai.utils.exporters import (
    OwaspPdfExporter,
    export_to_csv,
    export_to_json,
)


async def basic_scan_example():
    """Basic OWASP security scan."""
    print("=== Basic OWASP Scan ===\n")
    
    scanner = OwaspScanner(mode="safe")
    result = await scanner.scan("https://example.com")
    
    print(f"Target: {result.target}")
    print(f"Overall Grade: {result.overall_grade}")
    print(f"Overall Score: {result.overall_score}")
    print(f"Total Findings: {len(result.all_findings)}")
    print(f"Scan Duration: {result.scan_duration:.2f}s")
    
    # Print findings by category
    for category in result.categories:
        if category.findings:
            print(f"\n{category.category_id}: {category.category_name} [Grade: {category.grade}]")
            for finding in category.findings:
                print(f"  - [{finding.severity.value}] {finding.title}")


async def deep_scan_example():
    """Deep scan with active probing."""
    print("\n=== Deep Scan with Active Probing ===\n")
    
    scanner = OwaspScanner(
        mode="deep",
        timeout=15.0,
    )
    
    result = await scanner.scan("https://example.com")
    
    print(f"Scan Mode: {result.scan_mode.value}")
    print(f"Critical Findings: {len(result.critical_findings)}")
    print(f"High Findings: {len(result.high_findings)}")
    
    # Print critical findings
    if result.critical_findings:
        print("\n⚠️  CRITICAL FINDINGS:")
        for finding in result.critical_findings:
            print(f"  - {finding.title}")
            print(f"    {finding.description}")
            print(f"    Evidence: {finding.evidence}")


async def category_specific_scan():
    """Scan specific OWASP categories."""
    print("\n=== Category-Specific Scan ===\n")
    
    # Focus on crypto and misconfiguration
    scanner = OwaspScanner(
        mode="safe",
        categories=["A02", "A05"],
    )
    
    result = await scanner.scan("https://example.com")
    
    print(f"Scanned Categories: {', '.join(result.enabled_categories)}")
    
    for category in result.categories:
        print(f"\n{category.category_id}: {category.category_name}")
        print(f"  Grade: {category.grade}")
        print(f"  Score: {category.category_score}")
        print(f"  Findings: {len(category.findings)}")


async def batch_scan_example():
    """Scan multiple targets."""
    print("\n=== Batch Scan Multiple Targets ===\n")
    
    scanner = OwaspScanner(mode="safe")
    
    targets = [
        "https://example.com",
        "https://google.com",
        "https://github.com",
    ]
    
    batch_result = await scanner.batch_scan(targets, max_concurrent=3)
    
    print(f"Total Targets: {batch_result.total_targets}")
    print(f"Successful Scans: {batch_result.successful_scans}")
    print(f"Failed Scans: {batch_result.failed_scans}")
    print(f"Average Grade: {batch_result.average_grade}")
    
    # Print summary for each target
    for result in batch_result.results:
        print(f"\n{result.target}: Grade {result.overall_grade} ({len(result.all_findings)} findings)")


async def export_pdf_example():
    """Export scan results to PDF."""
    print("\n=== Export to PDF ===\n")
    
    scanner = OwaspScanner(mode="safe")
    result = await scanner.scan("https://example.com")
    
    # Export with Nginx-specific remediation
    exporter = OwaspPdfExporter(tech_stack="nginx")
    output_path = "owasp-security-report.pdf"
    exporter.export(result, output_path)
    
    print(f"✓ PDF report generated: {output_path}")


async def export_json_example():
    """Export scan results to JSON."""
    print("\n=== Export to JSON ===\n")
    
    scanner = OwaspScanner(mode="safe")
    result = await scanner.scan("https://example.com")
    
    # Export with full remediation details
    output_path = "owasp-scan-results.json"
    export_to_json(
        result,
        output_path,
        include_remediation=True,
        tech_stack="apache",
    )
    
    print(f"✓ JSON results exported: {output_path}")
    
    # Also export without remediation for smaller file size
    compact_path = "owasp-scan-compact.json"
    export_to_json(result, compact_path, include_remediation=False)
    print(f"✓ Compact JSON exported: {compact_path}")


async def export_csv_example():
    """Export scan results to CSV."""
    print("\n=== Export to CSV ===\n")
    
    scanner = OwaspScanner(mode="safe")
    result = await scanner.scan("https://example.com")
    
    output_path = "owasp-findings.csv"
    export_to_csv(result, output_path, tech_stack="generic")
    
    print(f"✓ CSV exported: {output_path}")


async def severity_filtering_example():
    """Filter findings by severity."""
    print("\n=== Severity Filtering ===\n")
    
    scanner = OwaspScanner(mode="deep")
    result = await scanner.scan("https://example.com")
    
    # Get only critical and high severity findings
    critical_high = [
        f for f in result.all_findings
        if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
    ]
    
    print(f"Total Findings: {len(result.all_findings)}")
    print(f"Critical + High: {len(critical_high)}")
    
    # Group by severity
    by_severity = {}
    for finding in result.all_findings:
        severity = finding.severity.value
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(finding)
    
    print("\nFindings by Severity:")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = len(by_severity.get(severity, []))
        print(f"  {severity}: {count}")


async def remediation_example():
    """Access remediation information."""
    print("\n=== Remediation Information ===\n")
    
    from offensive_ai.utils.owasp_remediation import get_remediation
    
    scanner = OwaspScanner(mode="safe")
    result = await scanner.scan("https://example.com")
    
    # Get remediation for first finding
    if result.all_findings:
        finding = result.all_findings[0]
        
        print(f"Finding: {finding.title}")
        print(f"Severity: {finding.severity.value}")
        print(f"CWE ID: CWE-{finding.cwe_id}")
        
        # Get tech-specific remediation
        remediation = get_remediation(finding.remediation_key, tech_stack="nginx")
        
        if remediation:
            print(f"\nRemediation Steps:")
            for i, step in enumerate(remediation.steps, 1):
                print(f"  {i}. {step}")
            
            print(f"\nCode Example (Nginx):")
            if "nginx" in remediation.code_examples:
                print(remediation.code_examples["nginx"])
            
            print(f"\nReferences:")
            for ref in remediation.references:
                print(f"  - {ref}")


async def custom_analysis_example():
    """Perform custom analysis on scan results."""
    print("\n=== Custom Analysis ===\n")
    
    scanner = OwaspScanner(mode="safe")
    result = await scanner.scan("https://example.com")
    
    # Analyze security posture
    analysis = {
        "grade": result.overall_grade,
        "score": result.overall_score,
        "total_findings": len(result.all_findings),
        "critical_count": len(result.critical_findings),
        "high_count": len(result.high_findings),
        "categories_with_issues": sum(1 for c in result.categories if c.findings),
        "worst_category": None,
        "best_category": None,
    }
    
    # Find worst category
    worst_score = 0
    for category in result.categories:
        if category.testable and category.category_score > worst_score:
            worst_score = category.category_score
            analysis["worst_category"] = f"{category.category_id}: {category.category_name}"
    
    # Find best category (testable with no findings)
    for category in result.categories:
        if category.testable and not category.findings:
            analysis["best_category"] = f"{category.category_id}: {category.category_name}"
            break
    
    print("Security Posture Analysis:")
    for key, value in analysis.items():
        print(f"  {key}: {value}")
    
    # Risk assessment
    if analysis["critical_count"] > 0:
        print("\n⚠️  Risk Level: CRITICAL - Immediate action required")
    elif analysis["high_count"] > 3:
        print("\n⚠️  Risk Level: HIGH - Address findings promptly")
    elif result.overall_grade in ["C", "D"]:
        print("\n⚠️  Risk Level: MEDIUM - Improvements recommended")
    else:
        print("\n✓ Risk Level: LOW - Good security posture")


async def main():
    """Run all examples."""
    
    # Note: These examples use example.com which may not be accessible
    # or may not have vulnerabilities. Replace with your own target for testing.
    
    try:
        await basic_scan_example()
        await deep_scan_example()
        await category_specific_scan()
        await batch_scan_example()
        await export_pdf_example()
        await export_json_example()
        await export_csv_example()
        await severity_filtering_example()
        await remediation_example()
        await custom_analysis_example()
        
        print("\n=== All Examples Complete ===")
        
    except Exception as e:
        print(f"\nError running examples: {e}")
        print("Note: These examples require network access to scan targets.")
        print("Replace 'example.com' with your own target for testing.")


if __name__ == "__main__":
    asyncio.run(main())
