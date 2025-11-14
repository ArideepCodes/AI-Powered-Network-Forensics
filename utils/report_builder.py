from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os

def generate_forensic_report(packets_df, threats, analysis_results, output_filename='forensic_report.pdf'):
    doc = SimpleDocTemplate(output_filename, pagesize=letter,
                            rightMargin=72, leftMargin=72,
                            topMargin=72, bottomMargin=18)
    
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=12
    )
    
    title = Paragraph("🔒 Network Packet Forensic Analysis Report", title_style)
    story.append(title)
    story.append(Spacer(1, 0.2 * inch))
    
    report_info = [
        ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ['Total Packets Analyzed:', str(len(packets_df))],
        ['Analysis Tool:', 'AI-Powered Network Packet Forensics Analyzer'],
        ['Created by:', 'Arideep Kanshabanik'],
        ['Email:', 'arideepkanshabanik@gmail.com']
    ]
    
    info_table = Table(report_info, colWidths=[2.5*inch, 3.5*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#ecf0f1')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2c3e50')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7'))
    ]))
    
    story.append(info_table)
    story.append(Spacer(1, 0.3 * inch))
    
    story.append(Paragraph("📊 Executive Summary", heading_style))
    
    if not packets_df.empty:
        protocol_dist = packets_df['protocol'].value_counts()
        protocol_summary = ', '.join([f"{proto}: {count}" for proto, count in protocol_dist.items()])
        
        summary_text = f"""
        <para>
        This forensic analysis examined {len(packets_df)} network packets captured during the session.
        The traffic contained the following protocols: {protocol_summary}.
        </para>
        """
        story.append(Paragraph(summary_text, normal_style))
    
    story.append(Spacer(1, 0.2 * inch))
    
    story.append(Paragraph("🚨 Threat Detection Summary", heading_style))
    
    if threats:
        from collections import Counter
        threat_counts = Counter(threats)
        
        threat_data = [['Threat Type', 'Count', 'Percentage']]
        for threat, count in threat_counts.items():
            percentage = (count / len(threats)) * 100
            threat_data.append([threat, str(count), f"{percentage:.1f}%"])
        
        threat_table = Table(threat_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2c3e50')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7')),
            ('TOPPADDING', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8)
        ]))
        
        story.append(threat_table)
    else:
        story.append(Paragraph("No threat data available.", normal_style))
    
    story.append(Spacer(1, 0.3 * inch))
    
    story.append(Paragraph("📋 Detailed Packet Analysis", heading_style))
    
    if not packets_df.empty and len(analysis_results) > 0:
        sample_size = min(20, len(analysis_results))
        story.append(Paragraph(f"<para>(Showing first {sample_size} packets)</para>", normal_style))
        story.append(Spacer(1, 0.1 * inch))
        
        for idx, result in enumerate(analysis_results[:sample_size]):
            packet_text = f"""
            <para>
            <b>Packet #{result.get('packet_num', idx+1)}:</b><br/>
            Source: {result.get('src_ip', 'N/A')}:{result.get('src_port', 'N/A')} → 
            Destination: {result.get('dst_ip', 'N/A')}:{result.get('dst_port', 'N/A')}<br/>
            Protocol: {result.get('protocol', 'N/A')} | Threat: {result.get('threat', 'Unknown')} | 
            Risk: {result.get('risk_score', 0):.1f}%<br/>
            </para>
            """
            story.append(Paragraph(packet_text, normal_style))
            story.append(Spacer(1, 0.05 * inch))
    
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("📌 Recommendations", heading_style))
    
    recommendations = """
    <para>
    Based on the forensic analysis, the following actions are recommended:<br/>
    1. Monitor any flagged suspicious IPs continuously<br/>
    2. Implement stricter firewall rules for detected anomalies<br/>
    3. Review security policies and update IDS/IPS signatures<br/>
    4. Conduct periodic security audits and penetration testing<br/>
    5. Maintain comprehensive logging for future investigations<br/>
    </para>
    """
    story.append(Paragraph(recommendations, normal_style))
    
    story.append(Spacer(1, 0.3 * inch))
    
    footer_text = f"""
    <para alignment="center">
    <b>AI-Powered Network Packet Forensics Analyzer</b><br/>
    Created by Arideep Kanshabanik<br/>
    Email: arideepkanshabanik@gmail.com | GitHub: github.com/ArideepCodes<br/>
    Portfolio: arideep.framer.ai<br/>
    Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}<br/>
    </para>
    """
    story.append(Paragraph(footer_text, normal_style))
    
    doc.build(story)
    
    return output_filename
