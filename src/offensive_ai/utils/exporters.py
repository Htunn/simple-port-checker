"""
Export utilities for OWASP scan results.

Supports exporting to PDF, CSV, and JSON formats with optional remediation details.
"""

import csv
import json
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    PageBreak,
    KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

from ..models.owasp_result import OwaspScanResult, SeverityLevel
from ..utils.owasp_remediation import get_remediation, get_category_info


class OwaspPdfExporter:
    """Generate PDF reports for OWASP scan results."""
    
    def __init__(self, tech_stack: str = "generic"):
        """
        Initialize PDF exporter.
        
        Args:
            tech_stack: Technology stack for remediation examples
        """
        self.tech_stack = tech_stack
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
        ))
        
        # Subsection
        self.styles.add(ParagraphStyle(
            name='SubSection',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=8,
        ))
    
    def export(self, result: OwaspScanResult, filepath: str):
        """
        Export OWASP scan result to PDF.
        
        Args:
            result: OWASP scan result to export
            filepath: Output PDF file path
        """
        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=inch,
            bottomMargin=inch,
        )
        
        story = []
        
        # Cover page
        story.extend(self._create_cover_page(result))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(result))
        story.append(PageBreak())
        
        # Category details
        for category in result.categories:
            story.extend(self._create_category_section(category))
            if category.findings:  # Only add page break if there were findings
                story.append(PageBreak())
        
        # Appendix with references
        story.extend(self._create_appendix())
        
        # Build PDF
        doc.build(story)
    
    def _create_cover_page(self, result: OwaspScanResult) -> list:
        """Create PDF cover page."""
        elements = []
        
        # Title
        elements.append(Spacer(1, 1.5 * inch))
        elements.append(Paragraph(
            "OWASP Top 10 2021<br/>Security Assessment Report",
            self.styles['CustomTitle']
        ))
        
        elements.append(Spacer(1, 0.5 * inch))
        
        # Overall grade with color
        grade_color = self._get_grade_color(result.overall_grade)
        grade_text = f'<font size="48" color="{grade_color}"><b>{result.overall_grade}</b></font>'
        elements.append(Paragraph(grade_text, self.styles['CustomTitle']))
        
        elements.append(Spacer(1, 0.5 * inch))
        
        # Target info
        info_data = [
            ["Target:", result.target],
            ["Scan Mode:", result.scan_mode.value.upper()],
            ["Scan Date:", result.timestamp.strftime("%Y-%m-%d %H:%M:%S")],
            ["Duration:", f"{result.scan_duration:.2f} seconds"],
            ["Overall Score:", str(result.overall_score)],
            ["Total Findings:", str(len(result.all_findings))],
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(info_table)
        
        return elements
    
    def _create_executive_summary(self, result: OwaspScanResult) -> list:
        """Create executive summary section."""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))
        
        # Summary text
        summary_text = f"""
        This report presents the results of an OWASP Top 10 2021 security assessment 
        performed on <b>{result.target}</b>. The scan was conducted in <b>{result.scan_mode.value}</b> mode
        and identified <b>{len(result.all_findings)}</b> security findings across 
        <b>{len([c for c in result.categories if c.findings])}</b> OWASP categories.
        """
        elements.append(Paragraph(summary_text, self.styles['BodyText']))
        elements.append(Spacer(1, 0.2 * inch))
        
        # Critical findings alert
        if result.has_critical:
            critical_count = len(result.critical_findings)
            alert_text = f"""
            <font color="red"><b>⚠ CRITICAL: This assessment identified {critical_count} 
            CRITICAL severity finding(s) that require immediate attention.</b></font>
            """
            elements.append(Paragraph(alert_text, self.styles['BodyText']))
            elements.append(Spacer(1, 0.2 * inch))
        
        # Severity breakdown
        severity_data = [
            ["Severity", "Count"],
            ["Critical", str(len([f for f in result.all_findings if f.severity == SeverityLevel.CRITICAL]))],
            ["High", str(len([f for f in result.all_findings if f.severity == SeverityLevel.HIGH]))],
            ["Medium", str(len([f for f in result.all_findings if f.severity == SeverityLevel.MEDIUM]))],
            ["Low", str(len([f for f in result.all_findings if f.severity == SeverityLevel.LOW]))],
        ]
        
        severity_table = Table(severity_data, colWidths=[3*inch, 2*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        elements.append(severity_table)
        elements.append(Spacer(1, 0.3 * inch))
        
        # Category grades table
        elements.append(Paragraph("Grades by OWASP Category", self.styles['SubSection']))
        elements.append(Spacer(1, 0.1 * inch))
        
        grade_data = [["Category", "Name", "Grade", "Findings"]]
        for category in result.categories:
            grade_data.append([
                category.category_id,
                category.category_name,
                category.grade if category.testable else "N/A",
                str(len(category.findings)) if category.testable else "Not Testable",
            ])
        
        grade_table = Table(grade_data, colWidths=[0.8*inch, 3*inch, 0.8*inch, 1*inch])
        grade_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
        ]))
        
        elements.append(grade_table)
        
        return elements
    
    def _create_category_section(self, category) -> list:
        """Create section for an OWASP category."""
        elements = []
        
        # Category header
        header_text = f"{category.category_id}: {category.category_name} [Grade: {category.grade}]"
        elements.append(Paragraph(header_text, self.styles['SectionHeader']))
        
        # Check if not testable
        if not category.testable:
            elements.append(Spacer(1, 0.1 * inch))
            not_testable_text = f"""
            <font color="gray"><i>This category cannot be tested via external scanning.<br/>
            {category.not_testable_reason}</i></font>
            """
            elements.append(Paragraph(not_testable_text, self.styles['BodyText']))
            return elements
        
        # If no findings
        if not category.findings:
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph(
                '<font color="green"><b>✓ No issues found in this category</b></font>',
                self.styles['BodyText']
            ))
            return elements
        
        elements.append(Spacer(1, 0.2 * inch))
        
        # Category description
        category_info = get_category_info(category.category_id)
        if category_info:
            elements.append(Paragraph(category_info['description'], self.styles['BodyText']))
            elements.append(Spacer(1, 0.2 * inch))
        
        # Findings
        for idx, finding in enumerate(category.findings, 1):
            finding_elements = self._create_finding_section(finding, idx)
            elements.append(KeepTogether(finding_elements))
            elements.append(Spacer(1, 0.2 * inch))
        
        return elements
    
    def _create_finding_section(self, finding, number: int) -> list:
        """Create section for a single finding."""
        elements = []
        
        # Finding title with severity
        severity_color = self._get_severity_color(finding.severity)
        title_text = f"""
        <b>Finding {number}: {finding.title}</b>
        <font color="{severity_color}"> [{finding.severity.value}]</font>
        """
        elements.append(Paragraph(title_text, self.styles['SubSection']))
        
        # Description
        elements.append(Paragraph(f"<b>Description:</b> {finding.description}", self.styles['BodyText']))
        
        # Evidence
        if finding.evidence:
            elements.append(Paragraph(f"<b>Evidence:</b> <font face='Courier'>{finding.evidence}</font>", self.styles['BodyText']))
        
        # CWE
        if finding.cwe_id:
            elements.append(Paragraph(f"<b>CWE ID:</b> CWE-{finding.cwe_id}", self.styles['BodyText']))
        
        # Remediation
        remediation = get_remediation(finding.remediation_key, self.tech_stack)
        if remediation:
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph("<b>Remediation:</b>", self.styles['BodyText']))
            
            # Steps
            for step in remediation.steps:
                elements.append(Paragraph(f"• {step}", self.styles['BodyText']))
            
            # Code examples
            if remediation.code_examples:
                elements.append(Spacer(1, 0.05 * inch))
                elements.append(Paragraph("<b>Code Example:</b>", self.styles['BodyText']))
                for tech, code in remediation.code_examples.items():
                    code_text = f"<font face='Courier' size='8'>{code[:500]}...</font>" if len(code) > 500 else f"<font face='Courier' size='8'>{code}</font>"
                    elements.append(Paragraph(f"<i>{tech}:</i>", self.styles['BodyText']))
                    elements.append(Paragraph(code_text, self.styles['BodyText']))
        
        return elements
    
    def _create_appendix(self) -> list:
        """Create appendix with references."""
        elements = []
        
        elements.append(Paragraph("References", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2 * inch))
        
        references = [
            "OWASP Top 10 2021: https://owasp.org/Top10/2021/",
            "OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/",
            "Mozilla Web Security: https://infosec.mozilla.org/guidelines/web_security",
            "SSL Labs: https://www.ssllabs.com/",
        ]
        
        for ref in references:
            elements.append(Paragraph(f"• {ref}", self.styles['BodyText']))
        
        return elements
    
    def _get_grade_color(self, grade: str) -> str:
        """Get color for grade."""
        colors_map = {
            "A": "#27ae60",
            "B": "#2ecc71",
            "C": "#f39c12",
            "D": "#e67e22",
            "F": "#e74c3c",
            "N/A": "#95a5a6",
        }
        return colors_map.get(grade, "#000000")
    
    def _get_severity_color(self, severity: SeverityLevel) -> str:
        """Get color for severity level."""
        colors_map = {
            SeverityLevel.CRITICAL: "#8b0000",
            SeverityLevel.HIGH: "#e74c3c",
            SeverityLevel.MEDIUM: "#f39c12",
            SeverityLevel.LOW: "#3498db",
        }
        return colors_map.get(severity, "#000000")


def export_to_csv(result: OwaspScanResult, filepath: str, tech_stack: str = "generic"):
    """
    Export OWASP scan result to CSV format.
    
    Args:
        result: OWASP scan result
        filepath: Output CSV file path
        tech_stack: Technology stack for remediation (not used in CSV, but kept for consistency)
    """
    with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Category ID',
            'Category Name',
            'Severity',
            'Title',
            'Description',
            'CWE ID',
            'Score',
            'Evidence',
        ]
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for category in result.categories:
            for finding in category.findings:
                writer.writerow({
                    'Category ID': finding.category,
                    'Category Name': category.category_name,
                    'Severity': finding.severity.value,
                    'Title': finding.title,
                    'Description': finding.description,
                    'CWE ID': finding.cwe_id or '',
                    'Score': finding.score,
                    'Evidence': finding.evidence or '',
                })


def export_to_json(
    result: OwaspScanResult,
    filepath: str,
    include_remediation: bool = True,
    tech_stack: Optional[str] = None,
):
    """
    Export OWASP scan result to JSON format.
    
    Args:
        result: OWASP scan result
        filepath: Output JSON file path
        include_remediation: Whether to include remediation details
        tech_stack: Technology stack for remediation filtering
    """
    data = result.to_dict()
    
    # Optionally add remediation details
    if include_remediation:
        for category in data['categories']:
            for finding in category['findings']:
                remediation_key = finding['remediation_key']
                tech = tech_stack or "generic"
                remediation = get_remediation(remediation_key, tech)
                
                if remediation:
                    finding['remediation'] = {
                        'description': remediation.description,
                        'severity_rationale': remediation.severity_rationale,
                        'steps': remediation.steps,
                        'code_examples': remediation.code_examples,
                        'references': remediation.references,
                        'cwe_ids': remediation.cwe_ids,
                    }
    
    with open(filepath, 'w', encoding='utf-8') as jsonfile:
        json.dump(data, jsonfile, indent=2, ensure_ascii=False)
