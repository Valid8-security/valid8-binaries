# Parry (C) by Valid8 Security. Written by Andy Kurapati and Shreyan Mitra
"""
PDF Export Module for Compliance Reports

Generates professional PDF compliance reports with:
- Executive summary with charts
- Detailed vulnerability breakdowns
- Control/requirement status tables
- Remediation recommendations
- Company branding and logos

Supports: SOC2, ISO 27001, PCI-DSS, OWASP Top 10, and combined reports
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import io
import base64

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class PDFComplianceExporter:
    """
    Professional PDF exporter for compliance reports
    
    Features:
    - Multi-page reports with headers/footers
    - Executive summary with charts
    - Detailed tables with color coding
    - Professional formatting with branding
    """
    
    def __init__(self, 
                 company_name: str = "Your Company",
                 logo_path: Optional[Path] = None,
                 pagesize=letter):
        """
        Initialize PDF exporter
        
        Args:
            company_name: Company name for report header
            logo_path: Path to company logo image (optional)
            pagesize: Page size (letter or A4)
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError(
                "reportlab is required for PDF export. "
                "Install with: pip install reportlab"
            )
        
        self.company_name = company_name
        self.logo_path = logo_path
        self.pagesize = pagesize
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=colors.HexColor('#1e293b'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Heading 1
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Heading 2
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#334155'),
            spaceAfter=10,
            spaceBefore=10,
            fontName='Helvetica-Bold'
        ))
        
        # Body text
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['BodyText'],
            fontSize=10,
            textColor=colors.HexColor('#475569'),
            spaceAfter=6,
            alignment=TA_JUSTIFY
        ))
        
        # Summary box
        self.styles.add(ParagraphStyle(
            name='SummaryBox',
            parent=self.styles['BodyText'],
            fontSize=11,
            textColor=colors.HexColor('#1e293b'),
            spaceAfter=8,
            leftIndent=10,
            rightIndent=10
        ))
    
    def _create_header_footer(self, canvas, doc):
        """Add header and footer to each page"""
        canvas.saveState()
        
        # Header
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#64748b'))
        canvas.drawString(
            0.75 * inch, 
            doc.height + doc.topMargin + 0.3 * inch,
            f"Parry Security - Compliance Report"
        )
        canvas.drawRightString(
            doc.width + doc.leftMargin + 0.75 * inch,
            doc.height + doc.topMargin + 0.3 * inch,
            datetime.now().strftime('%Y-%m-%d')
        )
        
        # Footer with page numbers
        canvas.drawCentredString(
            doc.width / 2 + doc.leftMargin,
            0.5 * inch,
            f"Page {doc.page}"
        )
        canvas.drawString(
            0.75 * inch,
            0.5 * inch,
            self.company_name
        )
        
        canvas.restoreState()
    
    def _create_severity_pie_chart(self, severity_counts: Dict[str, int]) -> Drawing:
        """Create pie chart for severity distribution"""
        drawing = Drawing(300, 200)
        pie = Pie()
        pie.x = 75
        pie.y = 50
        pie.width = 150
        pie.height = 150
        
        # Data
        labels = []
        data = []
        colors_list = []
        
        severity_config = {
            'critical': (colors.HexColor('#dc2626'), 'Critical'),
            'high': (colors.HexColor('#ea580c'), 'High'),
            'medium': (colors.HexColor('#ca8a04'), 'Medium'),
            'low': (colors.HexColor('#16a34a'), 'Low')
        }
        
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                data.append(count)
                color, label = severity_config[severity]
                labels.append(f"{label}: {count}")
                colors_list.append(color)
        
        if not data:
            data = [1]
            labels = ['No vulnerabilities']
            colors_list = [colors.HexColor('#22c55e')]
        
        pie.data = data
        pie.labels = labels
        pie.slices.strokeWidth = 0.5
        
        for i, color in enumerate(colors_list):
            pie.slices[i].fillColor = color
        
        drawing.add(pie)
        return drawing
    
    def _create_compliance_bar_chart(self, scores: Dict[str, float]) -> Drawing:
        """Create bar chart for compliance scores across standards"""
        drawing = Drawing(400, 200)
        bc = VerticalBarChart()
        bc.x = 50
        bc.y = 50
        bc.height = 125
        bc.width = 300
        
        bc.data = [[scores.get(std, 0) for std in scores.keys()]]
        bc.categoryAxis.categoryNames = list(scores.keys())
        bc.valueAxis.valueMin = 0
        bc.valueAxis.valueMax = 100
        
        bc.bars[0].fillColor = colors.HexColor('#3b82f6')
        bc.bars.strokeColor = colors.white
        
        drawing.add(bc)
        return drawing
    
    def _create_title_page(self, report_data: Dict[str, Any]) -> List:
        """Create title page elements"""
        elements = []
        
        # Logo if provided
        if self.logo_path and self.logo_path.exists():
            try:
                img = Image(str(self.logo_path), width=2*inch, height=1*inch)
                img.hAlign = 'CENTER'
                elements.append(img)
                elements.append(Spacer(1, 0.5*inch))
            except:
                pass  # Skip logo if can't load
        
        # Title
        elements.append(Paragraph(
            "Compliance Security Report",
            self.styles['CustomTitle']
        ))
        elements.append(Spacer(1, 0.3*inch))
        
        # Subtitle
        elements.append(Paragraph(
            f"<b>{self.company_name}</b>",
            self.styles['CustomHeading1']
        ))
        elements.append(Spacer(1, 0.2*inch))
        
        # Metadata table
        summary = report_data.get('summary', {})
        timestamp = datetime.now().strftime('%B %d, %Y at %H:%M')
        
        metadata = [
            ['Report Generated:', timestamp],
            ['Total Vulnerabilities:', str(summary.get('total_vulnerabilities', 0))],
            ['Standards Checked:', ', '.join(summary.get('standards_checked', []))],
        ]
        
        table = Table(metadata, colWidths=[2.5*inch, 3.5*inch])
        table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#64748b')),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#1e293b')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(table)
        elements.append(PageBreak())
        
        return elements
    
    def _create_executive_summary(self, report_data: Dict[str, Any]) -> List:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph(
            "Executive Summary",
            self.styles['CustomHeading1']
        ))
        elements.append(Spacer(1, 0.2*inch))
        
        summary = report_data.get('summary', {})
        
        # Summary text
        total_vulns = summary.get('total_vulnerabilities', 0)
        severity_dist = summary.get('by_severity', {})
        critical_count = severity_dist.get('critical', 0)
        high_count = severity_dist.get('high', 0)
        
        if total_vulns == 0:
            summary_text = (
                "This security scan found <b>no vulnerabilities</b> in the analyzed codebase. "
                "All checked compliance standards show full compliance. Continue maintaining "
                "secure coding practices and regular security audits."
            )
        elif critical_count > 0:
            summary_text = (
                f"This security scan identified <b>{total_vulns} total vulnerabilities</b>, "
                f"including <b><font color='#dc2626'>{critical_count} critical</font></b> "
                f"and <b><font color='#ea580c'>{high_count} high</font></b> severity issues. "
                f"<b>Immediate action is required</b> to address critical vulnerabilities before "
                f"they can be exploited."
            )
        else:
            summary_text = (
                f"This security scan identified <b>{total_vulns} total vulnerabilities</b> "
                f"across the analyzed codebase. While no critical issues were found, "
                f"remediation of {high_count} high severity issues is recommended."
            )
        
        elements.append(Paragraph(summary_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Severity distribution chart
        elements.append(Paragraph(
            "Vulnerability Severity Distribution",
            self.styles['CustomHeading2']
        ))
        elements.append(Spacer(1, 0.1*inch))
        
        pie_chart = self._create_severity_pie_chart(severity_dist)
        elements.append(pie_chart)
        elements.append(Spacer(1, 0.3*inch))
        
        # Compliance scores if multiple standards
        standards = [k for k in report_data.keys() if k != 'summary']
        if len(standards) > 1:
            elements.append(Paragraph(
                "Compliance Scores by Standard",
                self.styles['CustomHeading2']
            ))
            elements.append(Spacer(1, 0.1*inch))
            
            scores = {}
            for standard_key in standards:
                std_report = report_data[standard_key]
                score = std_report.get('compliance_score', 0)
                std_name = std_report.get('standard', standard_key.upper())
                scores[std_name] = score
            
            # Bar chart
            bar_chart = self._create_compliance_bar_chart(scores)
            elements.append(bar_chart)
            elements.append(Spacer(1, 0.2*inch))
        
        elements.append(PageBreak())
        return elements
    
    def _create_standard_section(self, 
                                 standard_key: str, 
                                 standard_data: Dict[str, Any]) -> List:
        """Create detailed section for a compliance standard"""
        elements = []
        
        # Standard header
        std_name = standard_data.get('standard', standard_key.upper())
        elements.append(Paragraph(
            f"{std_name} Compliance Report",
            self.styles['CustomHeading1']
        ))
        elements.append(Spacer(1, 0.2*inch))
        
        # Summary box
        score = standard_data.get('compliance_score', 0)
        status = standard_data.get('overall_status', 'UNKNOWN')
        
        if score >= 90:
            status_color = '#16a34a'
            status_text = 'COMPLIANT'
        elif score >= 70:
            status_color = '#ca8a04'
            status_text = 'PARTIAL COMPLIANCE'
        else:
            status_color = '#dc2626'
            status_text = 'NON-COMPLIANT'
        
        summary_box = [
            ['Compliance Score:', f"<b>{score:.1f}%</b>"],
            ['Status:', f"<b><font color='{status_color}'>{status_text}</font></b>"],
            ['Critical Findings:', str(standard_data.get('critical_findings', 0))],
        ]
        
        # Add standard-specific metrics
        if 'passed_controls' in standard_data:
            summary_box.append([
                'Passed Controls:',
                f"{standard_data['passed_controls']}/{standard_data.get('total_controls', 0)}"
            ])
        elif 'passed_requirements' in standard_data:
            summary_box.append([
                'Passed Requirements:',
                f"{standard_data['passed_requirements']}/{standard_data.get('total_requirements', 0)}"
            ])
        elif 'clean_categories' in standard_data:
            summary_box.append([
                'Clean Categories:',
                f"{standard_data['clean_categories']}/{standard_data.get('total_categories', 0)}"
            ])
        
        table = Table(summary_box, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#475569')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ]))
        
        elements.append(table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Controls/Requirements table
        requirements = standard_data.get('requirements', standard_data.get('categories', []))
        
        if requirements:
            elements.append(Paragraph(
                "Detailed Control Assessment",
                self.styles['CustomHeading2']
            ))
            elements.append(Spacer(1, 0.1*inch))
            
            # Table headers
            table_data = [[
                Paragraph('<b>Control ID</b>', self.styles['CustomBody']),
                Paragraph('<b>Control Name</b>', self.styles['CustomBody']),
                Paragraph('<b>Status</b>', self.styles['CustomBody']),
                Paragraph('<b>Findings</b>', self.styles['CustomBody'])
            ]]
            
            # Add rows
            for req in requirements:
                control_id = req.get('control_id', 'N/A')
                control_name = req.get('control_name', 'N/A')
                passed = req.get('passed', False)
                findings = req.get('findings', [])
                findings_count = len(findings)
                
                status_mark = '✓' if passed else '✗'
                status_color = '#16a34a' if passed else '#dc2626'
                
                table_data.append([
                    Paragraph(control_id, self.styles['CustomBody']),
                    Paragraph(control_name[:50] + '...' if len(control_name) > 50 else control_name, 
                             self.styles['CustomBody']),
                    Paragraph(f"<font color='{status_color}'><b>{status_mark}</b></font>", 
                             self.styles['CustomBody']),
                    Paragraph(str(findings_count), self.styles['CustomBody'])
                ])
            
            # Create table
            col_widths = [1*inch, 3*inch, 0.75*inch, 0.75*inch]
            req_table = Table(table_data, colWidths=col_widths, repeatRows=1)
            req_table.setStyle(TableStyle([
                # Header row
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                
                # Data rows
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('ALIGN', (2, 1), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                
                # Alternating row colors
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), 
                 [colors.white, colors.HexColor('#f8fafc')]),
                
                # Grid
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                
                # Padding
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))
            
            elements.append(req_table)
        
        elements.append(PageBreak())
        return elements
    
    def _create_recommendations(self, report_data: Dict[str, Any]) -> List:
        """Create recommendations section"""
        elements = []
        
        elements.append(Paragraph(
            "Remediation Recommendations",
            self.styles['CustomHeading1']
        ))
        elements.append(Spacer(1, 0.2*inch))
        
        summary = report_data.get('summary', {})
        total_vulns = summary.get('total_vulnerabilities', 0)
        
        if total_vulns == 0:
            elements.append(Paragraph(
                "No vulnerabilities were found. Continue following secure coding practices "
                "and conduct regular security audits to maintain this security posture.",
                self.styles['CustomBody']
            ))
        else:
            # Priority recommendations
            severity_dist = summary.get('by_severity', {})
            recommendations = []
            
            if severity_dist.get('critical', 0) > 0:
                recommendations.append(
                    f"<b>1. Address {severity_dist['critical']} Critical Vulnerabilities Immediately</b><br/>"
                    "Critical vulnerabilities pose immediate risk and should be patched within 24-48 hours. "
                    "Review all critical findings and apply recommended fixes."
                )
            
            if severity_dist.get('high', 0) > 0:
                recommendations.append(
                    f"<b>2. Remediate {severity_dist['high']} High Severity Issues</b><br/>"
                    "High severity vulnerabilities should be addressed within 1-2 weeks. "
                    "Prioritize issues in production-facing code."
                )
            
            if severity_dist.get('medium', 0) > 0:
                recommendations.append(
                    f"<b>3. Plan Fixes for {severity_dist['medium']} Medium Severity Issues</b><br/>"
                    "Medium severity issues should be scheduled for remediation within the next sprint or release cycle."
                )
            
            # General recommendations
            recommendations.extend([
                "<b>4. Implement Continuous Security Scanning</b><br/>"
                "Integrate Parry into your CI/CD pipeline to catch vulnerabilities before they reach production.",
                
                "<b>5. Security Training</b><br/>"
                "Conduct security awareness training for your development team focusing on the vulnerability types found in this scan.",
                
                "<b>6. Regular Audits</b><br/>"
                "Schedule quarterly comprehensive security audits and compliance reviews."
            ])
            
            for rec in recommendations:
                elements.append(Paragraph(rec, self.styles['CustomBody']))
                elements.append(Spacer(1, 0.15*inch))
        
        return elements
    
    def export_to_pdf(self, 
                      report_data: Dict[str, Any], 
                      output_path: Path,
                      include_charts: bool = True,
                      include_recommendations: bool = True) -> Path:
        """
        Export compliance report to PDF
        
        Args:
            report_data: Compliance report data dictionary
            output_path: Path where PDF should be saved
            include_charts: Whether to include charts (default: True)
            include_recommendations: Whether to include recommendations (default: True)
        
        Returns:
            Path to generated PDF file
        """
        # Create document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=self.pagesize,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.75*inch
        )
        
        # Build content
        elements = []
        
        # Title page
        elements.extend(self._create_title_page(report_data))
        
        # Executive summary (with charts if enabled)
        if include_charts:
            elements.extend(self._create_executive_summary(report_data))
        
        # Individual standard sections
        for standard_key, standard_data in report_data.items():
            if standard_key != 'summary':
                elements.extend(self._create_standard_section(standard_key, standard_data))
        
        # Recommendations
        if include_recommendations:
            elements.extend(self._create_recommendations(report_data))
        
        # Build PDF with header/footer callback
        doc.build(elements, onFirstPage=self._create_header_footer, 
                 onLaterPages=self._create_header_footer)
        
        return output_path


def export_compliance_report_to_pdf(
    report_data: Dict[str, Any],
    output_path: Path,
    company_name: str = "Your Company",
    logo_path: Optional[Path] = None
) -> Path:
    """
    Convenience function to export compliance report to PDF
    
    Args:
        report_data: Compliance report data from ComplianceReporter
        output_path: Where to save the PDF
        company_name: Company name for branding
        logo_path: Optional path to company logo
    
    Returns:
        Path to generated PDF
    
    Example:
        >>> from valid8.compliance import ComplianceReporter
        >>> from valid8.pdf_exporter import export_compliance_report_to_pdf
        >>> 
        >>> reporter = ComplianceReporter()
        >>> report = reporter.generate_report(vulnerabilities, standards=['soc2', 'owasp'])
        >>> export_compliance_report_to_pdf(
        ...     report, 
        ...     Path('compliance_report.pdf'),
        ...     company_name='Acme Corp'
        ... )
    """
    exporter = PDFComplianceExporter(
        company_name=company_name,
        logo_path=logo_path
    )
    
    return exporter.export_to_pdf(report_data, output_path)
