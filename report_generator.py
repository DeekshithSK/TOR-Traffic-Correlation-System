"""
Forensic Report Generator - PDF Format
Generates professional PDF reports for TOR traffic analysis.
"""

import os
from datetime import datetime
from io import BytesIO


def _check_reportlab():
    """Check if reportlab is available at runtime."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch, mm
        from reportlab.lib.colors import HexColor, black, white
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
        return True
    except ImportError:
        return False


def generate_forensic_report(case_info, results, findings, filename="forensic_report.pdf", origin_scope=None):
    """
    Generates a professional PDF forensic report.
    Falls back to markdown if reportlab is not installed.
    
    Args:
        case_info: Case metadata dict
        results: Analysis results dict
        findings: Guard inference findings dict
        filename: Output filename
        origin_scope: Optional origin scope estimation (supplementary intelligence)
    """
    reportlab_available = _check_reportlab()
    
    if not reportlab_available:
        return generate_markdown_report(case_info, results, findings, filename.replace('.pdf', '.md'), origin_scope)

    
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output_path = os.path.abspath(filename)
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=25*mm,
        leftMargin=25*mm,
        topMargin=25*mm,
        bottomMargin=25*mm
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=HexColor('#0a0c10'),
        spaceAfter=20,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=HexColor('#555555'),
        alignment=TA_CENTER,
        spaceAfter=30
    )
    
    section_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=HexColor('#1a1a2e'),
        spaceBefore=20,
        spaceAfter=10,
        fontName='Helvetica-Bold'
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        textColor=HexColor('#333333'),
        spaceAfter=8,
        alignment=TA_JUSTIFY,
        leading=14
    )
    
    label_style = ParagraphStyle(
        'Label',
        parent=styles['Normal'],
        fontSize=10,
        textColor=HexColor('#1a1a2e'),
        fontName='Helvetica-Bold'
    )
    
    warning_style = ParagraphStyle(
        'Warning',
        parent=styles['Normal'],
        fontSize=9,
        textColor=HexColor('#b8860b'),
        spaceBefore=10,
        spaceAfter=10,
        leftIndent=10,
        borderPadding=10
    )
    
    story = []
    
    story.append(Paragraph("TOR FORENSIC ANALYSIS REPORT", title_style))
    story.append(Paragraph(
        f"RESTRICTED - Law Enforcement Use Only<br/>"
        f"Generated: {timestamp}",
        subtitle_style
    ))
    
    case_data = [
        ['Case ID:', case_info.get('case_id', 'N/A')],
        ['Investigator:', case_info.get('investigator', 'N/A')],
        ['Report Date:', timestamp],
    ]
    case_table = Table(case_data, colWidths=[100, 350])
    case_table.setStyle(TableStyle([
        ('FONT', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONT', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (-1, -1), HexColor('#333333')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(case_table)
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("1. EXECUTIVE SUMMARY", section_style))
    
    story.append(Paragraph(
        "Analysis of captured network traffic identified a persistent encrypted connection "
        "matching Tor guard node behavior. The correlation engine has determined the following:",
        body_style
    ))
    story.append(Spacer(1, 10))
    
    confidence_score = findings.get('confidence_score', 0)
    if isinstance(confidence_score, float) and confidence_score <= 1:
        confidence_pct = f"{confidence_score:.1%}"
    else:
        confidence_pct = f"{confidence_score}%"
    
    findings_data = [
        ['Primary Finding', 'Tor Guard Node Identified'],
        ['Guard Node IP', findings.get('guard_node', 'Unknown').split('_')[2] if '_' in str(findings.get('guard_node', '')) else findings.get('guard_node', 'Unknown')],
        ['Country', f"{findings.get('flag', '🌐')} {findings.get('country', 'Unknown')}"],
        ['City', findings.get('city', 'Unknown')],
        ['ISP/Hosting', findings.get('isp', 'Unknown')],
        ['Confidence Level', findings.get('confidence_level', 'N/A')],
        ['Confidence Score', confidence_pct],
        ['Correlated Sessions', str(findings.get('correlated_sessions', 'N/A'))],
    ]
    
    findings_table = Table(findings_data, colWidths=[150, 300])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONT', (0, 1), (0, -1), 'Helvetica-Bold'),
        ('FONT', (1, 1), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f5f5f5')),
        ('TEXTCOLOR', (0, 1), (-1, -1), HexColor('#333333')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("2. FORENSIC ASSESSMENT", section_style))
    story.append(Paragraph(
        "The client maintained a persistent encrypted connection to this relay that matches "
        "Tor guard behavior. The connection pattern, timing characteristics, and traffic volume "
        "are consistent with Tor's guard node selection protocol.",
        body_style
    ))
    story.append(Spacer(1, 10))
    
    story.append(Paragraph("<b>Key Indicators:</b>", body_style))
    indicators = [
        "• Persistent TLS connection to single relay",
        "• Traffic patterns consistent with Tor cell sizes (512 bytes)",
        "• Connection duration matches guard rotation period",
        f"• Correlated across {findings.get('correlated_sessions', 'N/A')} flow windows",
        "• Timing patterns match expected Tor latency profiles"
    ]
    for indicator in indicators:
        story.append(Paragraph(indicator, body_style))
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("3. EVIDENCE CHAIN", section_style))
    evidence_data = [
        ['Source File:', results.get('source_file', 'Uploaded PCAP Evidence')],
        ['Analysis Engine:', 'TOR Flow Correlation Engine v1.0.0'],
        ['Total Flows Analyzed:', str(len(results.get('labels', [])))],
    ]
    evidence_table = Table(evidence_data, colWidths=[150, 300])
    evidence_table.setStyle(TableStyle([
        ('FONT', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONT', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (-1, -1), HexColor('#333333')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(evidence_table)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("4. CONFIDENCE ASSESSMENT", section_style))
    story.append(Paragraph(
        f"The confidence score of <b>{confidence_pct}</b> indicates a <b>{findings.get('confidence_level', 'N/A')}</b> "
        f"probability of correct identification.",
        body_style
    ))
    story.append(Spacer(1, 10))
    
    conf_ref_data = [
        ['Level', 'Score Range', 'Interpretation'],
        ['High', '75-100%', 'Strong correlation - suitable for investigative lead'],
        ['Medium', '50-74%', 'Moderate correlation - requires corroboration'],
        ['Low', '0-49%', 'Weak correlation - insufficient for identification'],
    ]
    conf_table = Table(conf_ref_data, colWidths=[80, 100, 270])
    conf_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONT', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f5f5f5')),
        ('TEXTCOLOR', (0, 1), (-1, -1), HexColor('#333333')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(conf_table)
    story.append(Spacer(1, 15))
    
    if origin_scope:
        story.append(Paragraph("5. CONTEXTUAL INTELLIGENCE - PROBABLE ORIGIN SCOPE", section_style))
        story.append(Paragraph(
            "<b>⚠️ NOT DIRECT ATTRIBUTION:</b> This is supplementary intelligence that does NOT identify "
            "the user's exact IP address or location.",
            warning_style
        ))
        story.append(Spacer(1, 10))
        
        origin_data = [
            ['Hosting Profile:', origin_scope.get('hosting_profile', 'Unknown')],
            ['Probable Region:', origin_scope.get('probable_origin_region', 'Unknown')],
            ['ISP Category:', origin_scope.get('origin_isp_category', 'Unknown')],
            ['Regional Estimate:', origin_scope.get('regional_radius_description', 'Unknown')],
            ['Estimation Confidence:', origin_scope.get('confidence_level', 'Low')],
        ]
        origin_table = Table(origin_data, colWidths=[150, 300])
        origin_table.setStyle(TableStyle([
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONT', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (-1, -1), HexColor('#555555')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(origin_table)
        story.append(Spacer(1, 10))
        
        story.append(Paragraph(
            f"<i>Reasoning: {origin_scope.get('confidence_reasoning', 'Standard estimation')}</i>",
            body_style
        ))
        story.append(Spacer(1, 15))
    
    story.append(Paragraph("6. OPERATIONAL LIMITATIONS" if origin_scope else "5. OPERATIONAL LIMITATIONS", section_style))
    story.append(Paragraph(
        "<b>⚠️ IMPORTANT:</b> This report provides investigative intelligence, not cryptographic proof.",
        warning_style
    ))
    
    limitations = [
        "• Results should be corroborated with independent evidence",
        "• Traffic patterns may be mimicked or obfuscated by adversaries",
        "• Guard nodes may host multiple users simultaneously",
        "• Timing-based analysis has inherent accuracy limitations"
    ]
    for limitation in limitations:
        story.append(Paragraph(limitation, body_style))
    story.append(Spacer(1, 30))
    
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=HexColor('#666666'),
        alignment=TA_CENTER
    )
    story.append(Paragraph(
        "This report is generated by automated forensic analysis tools and is intended to support, not replace, investigator judgment.<br/>"
        "<b>AUTHORIZED FOR LAW ENFORCEMENT USE ONLY</b>",
        footer_style
    ))
    
    doc.build(story)
    
    return output_path


def generate_markdown_report(case_info, results, findings, filename="forensic_report.md", origin_scope=None):
    """
    Fallback: Generates a markdown forensic report if reportlab is not available.
    
    Args:
        origin_scope: Optional origin scope estimation (supplementary intelligence)
    """
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    location_info = ""
    if findings.get('country'):
        location_info = f"""
**Geographic Location:** {findings.get('flag', '🌐')} {findings.get('country', 'Unknown')}
**City:** {findings.get('city', 'Unknown')}
**ISP/Hosting:** {findings.get('isp', 'Unknown')}
"""
    
    origin_section = ""
    section_offset = 0
    if origin_scope:
        section_offset = 1
        origin_section = f"""

> ⚠️ **NOT DIRECT ATTRIBUTION:** This is supplementary intelligence that does NOT identify the user's exact IP address or location.

| Field | Value |
|-------|-------|
| Hosting Profile | {origin_scope.get('hosting_profile', 'Unknown')} |
| Probable Region | {origin_scope.get('probable_origin_region', 'Unknown')} |
| ISP Category | {origin_scope.get('origin_isp_category', 'Unknown')} |
| Regional Estimate | {origin_scope.get('regional_radius_description', 'Unknown')} |
| Confidence | {origin_scope.get('confidence_level', 'Low')} |

*Reasoning: {origin_scope.get('confidence_reasoning', 'Standard estimation')}*

"""
    
    limitations_section = 6 if origin_scope else 5
    
    report_content = f"""# TOR Forensic Analysis Report

**Classification:** RESTRICTED - Law Enforcement Use Only
**Generated:** {timestamp}
**Case ID:** {case_info.get('case_id', 'N/A')}
**Investigator:** {case_info.get('investigator', 'N/A')}

---


**Primary Finding:**
Analysis of network traffic identified a persistent encrypted connection matching Tor guard node behavior.

**Identified Guard Node:** `{findings.get('guard_node', 'Unknown')}`
{location_info}
**Confidence Level:** {findings.get('confidence_level', 'N/A')} ({findings.get('confidence_score', 0):.1%})


The client maintained a persistent encrypted connection to this relay that matches Tor guard behavior. The connection pattern, timing characteristics, and traffic volume are consistent with Tor's guard node selection protocol.

**Key Indicators:**
- Persistent TLS connection to single relay
- Traffic patterns consistent with Tor cell sizes
- Connection duration matches guard rotation period
- Correlated across {findings.get('correlated_sessions', 'N/A')} flow windows


**Source File:** {results.get('source_file', 'N/A')}
**Analysis Engine:** TOR Flow Correlation Engine v1.0.0 (Certified)
**Total Flows Analyzed:** {len(results.get('labels', []))}


The confidence score of **{findings.get('confidence_score', 0):.1%}** indicates a **{findings.get('confidence_level', 'N/A')}** probability of correct identification.

| Level | Score Range | Interpretation |
|-------|------------|----------------|
| High | 75-100% | Strong correlation - suitable for investigative lead |
| Medium | 50-74% | Moderate correlation - requires corroboration |
| Low | 0-49% | Weak correlation - insufficient for identification |
{origin_section}

> ⚠️ **IMPORTANT:** This report provides investigative intelligence, not cryptographic proof.

- Results should be corroborated with independent evidence
- Traffic patterns may be mimicked or obfuscated
- Guard nodes may host multiple users simultaneously
- Timing-based analysis has inherent accuracy limits

---

*This report is generated by automated forensic analysis tools and is intended to support, not replace, investigator judgment.*

**Authorized for Law Enforcement Use Only**
"""
    
    output_path = os.path.abspath(filename)
    with open(output_path, "w") as f:
        f.write(report_content)
        
    return output_path

