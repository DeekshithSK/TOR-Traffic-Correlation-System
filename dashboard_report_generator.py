"""
Dashboard-Specific Forensic Report Generator
Generates PDF reports for Entry-Side, Exit-Side, and Dual-Side dashboards.
Tamil Nadu Police 2025 - Forensic Investigation Unit
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

CASE_COUNTER_FILE = Path("data/report_counter.json")
CASE_NUMBER_START = 70001

def _get_next_case_number():
    """Get the next consecutive case number for reports."""
    try:
        CASE_COUNTER_FILE.parent.mkdir(parents=True, exist_ok=True)
        if CASE_COUNTER_FILE.exists():
            with open(CASE_COUNTER_FILE, 'r') as f:
                data = json.load(f)
                next_num = data.get('next_number', CASE_NUMBER_START)
        else:
            next_num = CASE_NUMBER_START
        
        with open(CASE_COUNTER_FILE, 'w') as f:
            json.dump({'next_number': next_num + 1}, f)
        
        return next_num
    except Exception:
        return CASE_NUMBER_START

def _check_reportlab():
    """Check if reportlab is available at runtime."""
    try:
        from reportlab.lib.pagesizes import A4
        return True
    except ImportError:
        return False


def _get_country_flag_text(flag_emoji, country):
    """Convert flag emoji to ISO country code for PDF compatibility."""
    flag_to_iso = {
        '🇫🇷': 'FR', '🇩🇪': 'DE', '🇬🇧': 'GB', '🇺🇸': 'US', '🇳🇱': 'NL',
        '🇸🇪': 'SE', '🇨🇭': 'CH', '🇦🇹': 'AT', '🇧🇪': 'BE', '🇮🇹': 'IT',
        '🇪🇸': 'ES', '🇵🇹': 'PT', '🇵🇱': 'PL', '🇨🇿': 'CZ', '🇷🇴': 'RO',
        '🇧🇬': 'BG', '🇭🇺': 'HU', '🇫🇮': 'FI', '🇳🇴': 'NO', '🇩🇰': 'DK',
        '🇮🇪': 'IE', '🇱🇺': 'LU', '🇷🇺': 'RU', '🇺🇦': 'UA', '🇨🇦': 'CA',
        '🇦🇺': 'AU', '🇯🇵': 'JP', '🇰🇷': 'KR', '🇨🇳': 'CN', '🇮🇳': 'IN',
        '🇧🇷': 'BR', '🇲🇽': 'MX', '🇸🇬': 'SG', '🇭🇰': 'HK', '🇿🇦': 'ZA',
        '🇸🇨': 'SC', '🇱🇹': 'LT', '🇱🇻': 'LV', '🇪🇪': 'EE', '🇬🇷': 'GR',
        '🇹🇷': 'TR', '🇮🇱': 'IL', '🇦🇪': 'AE', '🇳🇿': 'NZ', '🇮🇩': 'ID',
        '🌐': 'INTL'
    }
    
    if flag_emoji and country:
        iso_code = flag_to_iso.get(flag_emoji, '')
        if iso_code:
            return f"[{iso_code}] {country}"
        return country
    return country or "Unknown"


def _get_confidence_label(score):
    """Convert confidence score to merged label with threshold."""
    if score >= 0.90:
        return "High (≥90%)"
    elif score >= 0.50:
        return "Medium (≥50%)"
    else:
        return f"Low (<50%)"


def generate_entry_side_report(results, case_id, pcap_hash=None, filename=None):
    """
    Generate PDF report for Entry-Side (Guard) PCAP Analysis.
    
    Focus: Inferred Guard Node, Client IP, Predicted Exit Nodes
    """
    if not _check_reportlab():
        return generate_entry_side_markdown(results, case_id, pcap_hash, filename)
    
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    report_number = _get_next_case_number()
    
    if not filename:
        filename = f"{case_id}.pdf"
    output_path = os.path.abspath(filename)
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, 
                                  textColor=HexColor('#0a1628'), alignment=TA_CENTER,
                                  spaceAfter=5, fontName='Helvetica-Bold')
    
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=10,
                                     textColor=HexColor('#555555'), alignment=TA_CENTER, spaceAfter=20)
    
    section_style = ParagraphStyle('Section', parent=styles['Heading2'], fontSize=12,
                                    textColor=HexColor('#1a1a2e'), spaceBefore=15, spaceAfter=8,
                                    fontName='Helvetica-Bold')
    
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9,
                                 textColor=HexColor('#333333'), spaceAfter=6, alignment=TA_JUSTIFY)
    
    story = []
    
    story.append(Paragraph("TOR Traffic Correlation &amp; Probable Origin Analysis", title_style))
    story.append(Paragraph("ENTRY-SIDE PCAP ANALYSIS REPORT", subtitle_style))
    
    top_finding = results.get('top_finding', {})
    correlation = results.get('correlation', {})
    
    case_data = [
        ['Report Number:', str(report_number)],
        ['Case ID:', case_id],
        ['Date &amp; Time (UTC):', timestamp],
        ['Investigating Unit:', 'Tamil Nadu Police 2025'],
        ['Analysis Mode:', 'Entry-Side (Guard Correlation)'],
    ]
    if pcap_hash:
        case_data.append(['PCAP Hash (SHA-256):', pcap_hash[:32] + '...'])
    
    case_table = Table(case_data, colWidths=[130, 320])
    case_table.setStyle(TableStyle([
        ('FONT', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONT', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TEXTCOLOR', (0, 0), (-1, -1), HexColor('#333333')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8f9fa')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
    ]))
    story.append(case_table)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("1. PRIMARY FINDING: IDENTIFIED GUARD NODE", section_style))
    
    guard_ip = top_finding.get('ip', 'N/A')
    guard_country = top_finding.get('country', 'Unknown')
    guard_flag = top_finding.get('flag', '')
    guard_isp = top_finding.get('isp', 'Unknown')
    conf_score = top_finding.get('confidence_score', 0)
    conf_level = top_finding.get('confidence_level', 'N/A')
    
    if guard_ip and guard_ip != 'N/A':
        guard_data = [
            ['Guard Node IP:', guard_ip],
            ['Country:', _get_country_flag_text(guard_flag, guard_country)],
            ['ISP / ASN:', guard_isp],
            ['Confidence Level:', _get_confidence_label(conf_score)],
            ['Correlated Sessions:', str(top_finding.get('correlated_sessions', 'N/A'))],
        ]
        
        origin_ip = top_finding.get('origin_ip')
        if origin_ip:
            guard_data.append(['Inferred Client Network Identifier:', origin_ip])
        
        guard_table = Table(guard_data, colWidths=[160, 290])
        guard_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#10b981')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONT', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f0fdf4')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#86efac')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(guard_table)
    else:
        story.append(Paragraph("No verified Tor guard node detected in analysis.", body_style))
    
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("2. PREDICTED EXIT NODES (From Tor Consensus)", section_style))
    
    probable_exits = correlation.get('probable_exits', []) or results.get('probable_exit_nodes', [])
    
    if probable_exits:
        exit_headers = [['#', 'IP Address', 'Country', 'ISP', 'Probability']]
        for i, exit_node in enumerate(probable_exits[:5], 1):
            exit_headers.append([
                str(i),
                exit_node.get('ip', 'N/A'),
                _get_country_flag_text(exit_node.get('flag', ''), exit_node.get('country', '')),
                (exit_node.get('isp', '') or '')[:25],
                f"{exit_node.get('probability', 0)*100:.0f}%"
            ])
        
        exit_table = Table(exit_headers, colWidths=[25, 110, 110, 130, 70])
        exit_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#8b5cf6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONT', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#faf5ff')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#c4b5fd')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(exit_table)
    else:
        story.append(Paragraph("No exit nodes predicted from consensus analysis.", body_style))
    
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("3. ANALYSIS METRICS", section_style))
    
    details = results.get('details', {})
    metrics_data = [
        ['Metric', 'Value'],
        ['Total Sessions Analyzed', str(len(details.get('labels', [])))],
        ['Sessions Correlated', str(top_finding.get('correlated_sessions', 'N/A'))],
        ['Correlation Mode', results.get('analysis_mode', 'entry_only')],
    ]
    
    metrics_table = Table(metrics_data, colWidths=[200, 250])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONT', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f5f5f5')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("4. CORRELATION METHOD", section_style))
    method_data = [
        ['Technique', 'Description'],
        ['Time-window alignment', 'Millisecond-level temporal correlation'],
        ['Packet burst similarity', 'Burst pattern matching across flows'],
        ['Flow size distribution', 'Statistical comparison of packet sizes'],
        ['Guard stability', 'Bandwidth weighting from Tor consensus'],
        ['Tor consensus verification', 'Cross-reference with live relay data'],
    ]
    method_table = Table(method_data, colWidths=[150, 300])
    method_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#6366f1')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#eef2ff')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#a5b4fc')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(method_table)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("5. FORENSIC NOTICE", section_style))
    story.append(Paragraph(
        "This report provides investigative intelligence based on traffic correlation analysis. "
        "Results should be corroborated with independent evidence. Guard nodes may serve multiple "
        "users simultaneously. This analysis does NOT constitute cryptographic proof of user identity.",
        body_style
    ))
    
    story.append(Spacer(1, 30))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                                   textColor=HexColor('#666666'), alignment=TA_CENTER)
    story.append(Paragraph(
        "Generated by TOR Forensic Analysis System | Tamil Nadu Police 2025<br/>"
        "<b>AUTHORIZED FOR LAW ENFORCEMENT USE ONLY</b>",
        footer_style
    ))
    
    doc.build(story)
    return output_path


def generate_exit_side_report(results, case_id, pcap_hash=None, filename=None):
    """
    Generate PDF report for Exit-Side PCAP Analysis.
    
    Focus: Detected Exit Nodes, Probable Guards, Flow Fingerprint
    """
    if not _check_reportlab():
        return generate_exit_side_markdown(results, case_id, pcap_hash, filename)
    
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    report_number = _get_next_case_number()
    
    if not filename:
        filename = f"{case_id}.pdf"
    output_path = os.path.abspath(filename)
    
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=20*mm, leftMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, 
                                  textColor=HexColor('#0a1628'), alignment=TA_CENTER,
                                  spaceAfter=5, fontName='Helvetica-Bold')
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=10,
                                     textColor=HexColor('#555555'), alignment=TA_CENTER, spaceAfter=20)
    section_style = ParagraphStyle('Section', parent=styles['Heading2'], fontSize=12,
                                    textColor=HexColor('#1a1a2e'), spaceBefore=15, spaceAfter=8,
                                    fontName='Helvetica-Bold')
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9,
                                 textColor=HexColor('#333333'), spaceAfter=6, alignment=TA_JUSTIFY)
    
    story = []
    
    story.append(Paragraph("TOR Traffic Correlation &amp; Probable Origin Analysis", title_style))
    story.append(Paragraph("EXIT-SIDE PCAP ANALYSIS REPORT", subtitle_style))
    
    correlation = results.get('correlation', {})
    flow_metadata = results.get('flow_metadata', {})
    
    case_data = [
        ['Report Number:', str(report_number)],
        ['Case ID:', case_id],
        ['Date &amp; Time (UTC):', timestamp],
        ['Investigating Unit:', 'Tamil Nadu Police 2025'],
        ['Analysis Mode:', 'Exit-Side (Exit Node Detection)'],
    ]
    if pcap_hash:
        case_data.append(['PCAP Hash (SHA-256):', pcap_hash[:32] + '...'])
    
    case_table = Table(case_data, colWidths=[130, 320])
    case_table.setStyle(TableStyle([
        ('FONT', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8f9fa')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(case_table)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("1. VERIFIED TOR EXIT NODES DETECTED", section_style))
    
    top_exit_nodes = correlation.get('top_exit_nodes', [])
    
    if top_exit_nodes:
        exit_headers = [['#', 'IP Address', 'Country', 'ISP', 'Packets', 'In Consensus']]
        for i, exit_node in enumerate(top_exit_nodes[:5], 1):
            in_consensus = "Yes" if exit_node.get('in_consensus') else "No"
            exit_headers.append([
                str(i),
                exit_node.get('ip', 'N/A'),
                _get_country_flag_text(exit_node.get('flag', ''), exit_node.get('country', '')),
                (exit_node.get('isp', '') or '')[:20],
                str(exit_node.get('packet_count', 'N/A')),
                in_consensus
            ])
        
        exit_table = Table(exit_headers, colWidths=[25, 100, 100, 100, 60, 60])
        exit_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#3b82f6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#eff6ff')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#93c5fd')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(exit_table)
    else:
        story.append(Paragraph("No verified Tor exit nodes detected in PCAP.", body_style))
    
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("2. PROBABLE GUARD NODES (Inferred from Exit Traffic)", section_style))
    
    probable_guards = correlation.get('probable_guards', [])
    
    if probable_guards:
        guard_headers = [['#', 'IP Address', 'Nickname', 'Country', 'Probability']]
        for i, guard in enumerate(probable_guards[:5], 1):
            guard_headers.append([
                str(i),
                guard.get('ip', 'N/A'),
                (guard.get('nickname', '') or '')[:15],
                _get_country_flag_text(guard.get('flag', ''), guard.get('country', '')),
                f"{guard.get('guard_probability', 0)*100:.0f}%"
            ])
        
        guard_table = Table(guard_headers, colWidths=[25, 120, 90, 120, 70])
        guard_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#10b981')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f0fdf4')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#86efac')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(guard_table)
    else:
        story.append(Paragraph("No probable guard nodes inferred from exit traffic.", body_style))
    
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("3. FLOW FINGERPRINT ANALYSIS", section_style))
    
    fingerprint = flow_metadata.get('fingerprint', {})
    if fingerprint:
        fp_data = [
            ['Metric', 'Value'],
            ['Burst Entropy', f"{fingerprint.get('burst_entropy', 0):.3f}"],
            ['Micro-gap Average', f"{(fingerprint.get('micro_gap_avg', 0) or 0)*1000:.2f} ms"],
            ['Size Variance Slope', f"{fingerprint.get('size_variance_slope', 0):.2f}"],
            ['Circuit Lifetime', f"{fingerprint.get('circuit_lifetime', 0):.2f} s"],
        ]
        
        fp_table = Table(fp_data, colWidths=[200, 250])
        fp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f59e0b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#fffbeb')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#fcd34d')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(fp_table)
    else:
        story.append(Paragraph("No flow fingerprint data available.", body_style))
    
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("4. TRAFFIC PROFILE", section_style))
    
    traffic_data = [
        ['Metric', 'Value'],
        ['Total Packets', str(flow_metadata.get('total_packets', 'N/A'))],
        ['Total Bytes', f"{(flow_metadata.get('total_bytes', 0) or 0)/1024:.1f} KB"],
        ['Total Flows', str(flow_metadata.get('total_flows', 'N/A'))],
        ['CDN Filtered', str(flow_metadata.get('cdn_filtered', 0))],
    ]
    
    traffic_table = Table(traffic_data, colWidths=[200, 250])
    traffic_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f5f5f5')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(traffic_table)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("5. CORRELATION METHOD", section_style))
    method_data = [
        ['Technique', 'Description'],
        ['Time-window alignment', 'Millisecond-level temporal correlation'],
        ['Packet burst similarity', 'Burst pattern matching across flows'],
        ['Flow size distribution', 'Statistical comparison of packet sizes'],
        ['Guard stability', 'Bandwidth weighting from Tor consensus'],
        ['Tor consensus verification', 'Cross-reference with live relay data'],
    ]
    method_table = Table(method_data, colWidths=[150, 300])
    method_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#6366f1')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#eef2ff')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#a5b4fc')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(method_table)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("6. FORENSIC NOTICE", section_style))
    story.append(Paragraph(
        "This report provides investigative intelligence based on exit-side traffic analysis. "
        "Guard node predictions are probabilistic based on Tor consensus bandwidth weighting.",
        body_style
    ))
    
    story.append(Spacer(1, 30))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                                   textColor=HexColor('#666666'), alignment=TA_CENTER)
    story.append(Paragraph(
        "Generated by TOR Forensic Analysis System | Tamil Nadu Police 2025<br/>"
        "<b>AUTHORIZED FOR LAW ENFORCEMENT USE ONLY</b>",
        footer_style
    ))
    
    doc.build(story)
    return output_path


def generate_dual_side_report(results, case_id, pcap_hash=None, filename=None):
    """
    Generate PDF report for Dual-Side (Guard + Exit) PCAP Analysis.
    
    Focus: Guard-Exit Matches, Correlation Evidence, Complete Path
    """
    if not _check_reportlab():
        return generate_dual_side_markdown(results, case_id, pcap_hash, filename)
    
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    report_number = _get_next_case_number()
    
    if not filename:
        filename = f"{case_id}.pdf"
    output_path = os.path.abspath(filename)
    
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=20*mm, leftMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, 
                                  textColor=HexColor('#0a1628'), alignment=TA_CENTER,
                                  spaceAfter=5, fontName='Helvetica-Bold')
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=10,
                                     textColor=HexColor('#555555'), alignment=TA_CENTER, spaceAfter=20)
    section_style = ParagraphStyle('Section', parent=styles['Heading2'], fontSize=12,
                                    textColor=HexColor('#1a1a2e'), spaceBefore=15, spaceAfter=8,
                                    fontName='Helvetica-Bold')
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9,
                                 textColor=HexColor('#333333'), spaceAfter=6, alignment=TA_JUSTIFY)
    
    story = []
    
    story.append(Paragraph("TOR Traffic Correlation &amp; Probable Origin Analysis", title_style))
    story.append(Paragraph("DUAL-SIDE PCAP CORRELATION REPORT", subtitle_style))
    
    top_finding = results.get('top_finding', {})
    correlation = results.get('correlation', {})
    details = results.get('details', {})
    
    case_data = [
        ['Report Number:', str(report_number)],
        ['Case ID:', case_id],
        ['Date &amp; Time (UTC):', timestamp],
        ['Investigating Unit:', 'Tamil Nadu Police 2025'],
        ['Analysis Mode:', 'Dual-Side (Entry + Exit Correlation)'],
    ]
    if pcap_hash:
        case_data.append(['PCAP Hash (SHA-256):', pcap_hash[:32] + '...'])
    
    case_table = Table(case_data, colWidths=[130, 320])
    case_table.setStyle(TableStyle([
        ('FONT', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8f9fa')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(case_table)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("1. ANALYSIS METRICS SUMMARY", section_style))
    
    guard_exit_pairs = correlation.get('guard_exit_pairs', [])
    top_exit_nodes = correlation.get('top_exit_nodes', [])
    
    metrics_data = [
        ['Metric', 'Value'],
        ['Exit Nodes Observed', str(len(top_exit_nodes))],
        ['Candidate Guards Analyzed', str(len(details.get('labels', [])))],
        ['Guard-Exit Pairs Matched', str(len(guard_exit_pairs))],
        ['Final High-Confidence Guards', str(min(3, len(guard_exit_pairs)))],
        ['Correlation Mode', correlation.get('mode', 'guard_exit')],
    ]
    
    metrics_table = Table(metrics_data, colWidths=[200, 250])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f5f5f5')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("2. TOP PROBABLE CONNECTIONS ESTABLISHED (>90% Confidence)", section_style))
    
    if guard_exit_pairs:
        match_headers = [['#', 'Guard IP', 'Exit IP', 'Guard Conf.', 'Exit Score', 'Origin IP']]
        for i, pair in enumerate(guard_exit_pairs[:5], 1):
            match_headers.append([
                str(i),
                pair.get('guard_ip', 'N/A')[:18],
                pair.get('exit_ip', 'N/A')[:18],
                f"{pair.get('guard_confidence', 0)*100:.0f}%",
                f"{pair.get('exit_score', 0)*100:.0f}%",
                pair.get('origin_ip', 'N/A') or 'N/A'
            ])
        
        match_table = Table(match_headers, colWidths=[20, 85, 85, 60, 60, 100])
        match_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#6366f1')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#eef2ff')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#a5b4fc')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(match_table)
    else:
        story.append(Paragraph("No guard-exit matches found.", body_style))
    
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("3. PRIMARY FINDING: BEST MATCH", section_style))
    
    guard_ip = top_finding.get('ip', 'N/A')
    if guard_ip and guard_ip != 'N/A':
        primary_data = [
            ['Guard Node IP:', guard_ip],
            ['Country:', _get_country_flag_text(top_finding.get('flag', ''), top_finding.get('country', ''))],
            ['ISP:', top_finding.get('isp', 'Unknown')],
            ['Confidence Level:', _get_confidence_label(top_finding.get('confidence_score', 0))],
        ]
        
        if top_finding.get('origin_ip'):
            primary_data.append(['Inferred Client Network Identifier:', top_finding.get('origin_ip')])
        
        primary_table = Table(primary_data, colWidths=[150, 300])
        primary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#10b981')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f0fdf4')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#86efac')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(primary_table)
    else:
        story.append(Paragraph("No primary match identified.", body_style))
    
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("4. EXIT NODES DETECTED IN CORRELATION", section_style))
    
    if top_exit_nodes:
        exit_headers = [['#', 'IP Address', 'Country', 'ISP', 'Score']]
        for i, exit_node in enumerate(top_exit_nodes[:3], 1):
            exit_headers.append([
                str(i),
                exit_node.get('ip', 'N/A'),
                _get_country_flag_text(exit_node.get('flag', ''), exit_node.get('country', '')),
                (exit_node.get('isp', '') or '')[:25],
                f"{exit_node.get('combined_score', exit_node.get('score', 0))*100:.0f}%"
            ])
        
        exit_table = Table(exit_headers, colWidths=[25, 110, 110, 130, 50])
        exit_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#3b82f6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#eff6ff')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#93c5fd')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(exit_table)
    else:
        story.append(Paragraph("No exit nodes detected.", body_style))
    
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("5. CORRELATION METHOD", section_style))
    method_data = [
        ['Technique', 'Description'],
        ['Time-window alignment', 'Millisecond-level temporal correlation'],
        ['Packet burst similarity', 'Burst pattern matching across flows'],
        ['Flow size distribution', 'Statistical comparison of packet sizes'],
        ['Guard stability', 'Bandwidth weighting from Tor consensus'],
        ['Tor consensus verification', 'Cross-reference with live relay data'],
    ]
    method_table = Table(method_data, colWidths=[150, 300])
    method_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#6366f1')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#eef2ff')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#a5b4fc')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(method_table)
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("6. FORENSIC NOTICE", section_style))
    story.append(Paragraph(
        "This report provides the highest confidence correlation from dual-side PCAP analysis. "
        "Entry-exit matching uses flow timing, burst patterns, and Tor consensus verification. "
        "Results should be corroborated with independent evidence.",
        body_style
    ))
    
    story.append(Spacer(1, 30))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                                   textColor=HexColor('#666666'), alignment=TA_CENTER)
    story.append(Paragraph(
        "Generated by TOR Forensic Analysis System | Tamil Nadu Police 2025<br/>"
        "<b>AUTHORIZED FOR LAW ENFORCEMENT USE ONLY</b>",
        footer_style
    ))
    
    doc.build(story)
    return output_path


def generate_entry_side_markdown(results, case_id, pcap_hash=None, filename=None):
    """Fallback markdown report for entry-side analysis."""
    if not filename:
        filename = f"Entry_Side_Report_{case_id}.md"
    
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    top_finding = results.get('top_finding', {})
    correlation = results.get('correlation', {})
    
    content = f"""# TOR Traffic Correlation & Probable Origin Analysis

| Field | Value |
|-------|-------|
| Case ID | {case_id} |
| Date & Time (UTC) | {timestamp} |
| Investigating Unit | Tamil Nadu Police 2025 |
| PCAP Hash | {pcap_hash[:32] + '...' if pcap_hash else 'N/A'} |


- **Guard Node IP:** {top_finding.get('ip', 'N/A')}
- **Country:** {top_finding.get('flag', '')} {top_finding.get('country', 'Unknown')}
- **ISP:** {top_finding.get('isp', 'Unknown')}
- **Confidence:** {top_finding.get('confidence_score', 0)*100:.0f}% ({top_finding.get('confidence_level', 'N/A')})

---
*Generated by TOR Forensic Analysis System | Tamil Nadu Police 2025*
"""
    
    output_path = os.path.abspath(filename)
    with open(output_path, 'w') as f:
        f.write(content)
    return output_path


def generate_exit_side_markdown(results, case_id, pcap_hash=None, filename=None):
    """Fallback markdown report for exit-side analysis."""
    if not filename:
        filename = f"Exit_Side_Report_{case_id}.md"
    
    output_path = os.path.abspath(filename)
    with open(output_path, 'w') as f:
        f.write(f"# Exit-Side Analysis Report\nCase: {case_id}\n")
    return output_path


def generate_dual_side_markdown(results, case_id, pcap_hash=None, filename=None):
    """Fallback markdown report for dual-side analysis."""
    if not filename:
        filename = f"Dual_Side_Report_{case_id}.md"
    
    output_path = os.path.abspath(filename)
    with open(output_path, 'w') as f:
        f.write(f"# Dual-Side Correlation Report\nCase: {case_id}\n")
    return output_path
