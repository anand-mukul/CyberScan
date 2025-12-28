from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import os
import re

class PDFReporter:
    def __init__(self):
        self.output_dir = "static/reports"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate(self, data):
        # 1. Prepare Filename
        domain = re.sub(r"https?://(www\.)?", "", data['target']).split('/')[0]
        filename = f"scan_report_{domain}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        # 2. Document Setup
        doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
        story = []
        styles = getSampleStyleSheet()

        # --- CUSTOM STYLES ---
        title_style = ParagraphStyle('MainTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor("#2c3e50"), spaceAfter=20)
        subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=12, textColor=colors.HexColor("#7f8c8d"))
        header_style = ParagraphStyle('Header', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor("#2980b9"), spaceBefore=15, spaceAfter=10)
        
        # --- HEADER SECTION ---
        # Draw a top colored bar (simulated with a wide table)
        story.append(Spacer(1, 10))
        story.append(Paragraph("<b>CYBERSCAN INTELLIGENCE</b>", title_style))
        story.append(Paragraph("<i>Automated Vulnerability Audit & Compliance Report</i>", subtitle_style))
        story.append(Spacer(1, 20))
        
        # --- EXECUTIVE SUMMARY GRID ---
        story.append(Paragraph("Executive Summary", header_style))
        
        # Color code the grade
        grade_color = colors.green if data['grade'] in ['A', 'B'] else colors.red
        
        summary_data = [
            [Paragraph("<b>Target URL:</b>", styles['Normal']), Paragraph(data['target'], styles['Normal'])],
            [Paragraph("<b>Scan Date:</b>", styles['Normal']), Paragraph(data['date'], styles['Normal'])],
            [Paragraph("<b>Risk Score:</b>", styles['Normal']), Paragraph(f"{data['risk_score']}/10", styles['Normal'])],
            [Paragraph("<b>Security Grade:</b>", styles['Normal']), Paragraph(f"<b><font color={grade_color}>{data['grade']}</font></b>", styles['Normal'])]
        ]
        
        t_summary = Table(summary_data, colWidths=[2*inch, 4*inch])
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#ecf0f1")), # Light grey label column
            ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor("#2c3e50")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#bdc3c7")),
        ]))
        story.append(t_summary)
        story.append(Spacer(1, 25))

        # --- VULNERABILITY FINDINGS ---
        story.append(Paragraph(f"Detailed Findings ({data['vuln_count']} Issues)", header_style))

        if data['vulnerabilities']:
            # Table Header
            table_data = [['Sev', 'Vulnerability', 'OWASP Category', 'Location']]
            
            for v in data['vulnerabilities']:
                # Truncate long URL
                short_url = (v['url'][:40] + '...') if len(v['url']) > 40 else v['url']
                
                # Severity Color
                sev_color = colors.red if v.get('severity') in ['High', 'Critical'] else colors.orange
                sev_text = Paragraph(f"<b><font color={sev_color}>{v.get('severity', 'Med')}</font></b>", styles['Normal'])
                
                table_data.append([
                    sev_text,
                    Paragraph(v['type'], styles['Normal']),
                    Paragraph(v.get('owasp', 'N/A'), styles['Normal']),
                    Paragraph(short_url, styles['Normal'])
                ])

            t_vuln = Table(table_data, colWidths=[0.8*inch, 1.8*inch, 1.8*inch, 2.5*inch])
            t_vuln.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#34495e")), # Dark Header
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.black),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f9f9f9")]) # Alternating rows
            ]))
            story.append(t_vuln)
        else:
            story.append(Paragraph("✅ No critical vulnerabilities were detected during this scan.", styles['Normal']))

        story.append(Spacer(1, 25))

        # --- MISSING HEADERS & PORTS ---
        story.append(Paragraph("Network & Configuration Analysis", header_style))
        
        # Headers List
        if data['headers']['missing']:
            story.append(Paragraph("<b>Missing Security Headers:</b>", styles['Normal']))
            for h in data['headers']['missing']:
                story.append(Paragraph(f"• <font color='orange'>{h}</font>", styles['BodyText']))
        else:
            story.append(Paragraph("• All recommended security headers are present.", styles['Normal']))

        story.append(Spacer(1, 10))
        
        # Open Ports List
        if data['ports']:
            story.append(Paragraph("<b>Open Ports Detected:</b>", styles['Normal']))
            port_list = ", ".join([str(p['port']) for p in data['ports']])
            story.append(Paragraph(f"• {port_list}", styles['BodyText']))
        else:
            story.append(Paragraph("• No exposed ports detected.", styles['Normal']))

        # --- FOOTER ---
        story.append(Spacer(1, 40))
        footer_text = "CONFIDENTIAL - GENERATED BY CyberScan"
        story.append(Paragraph(footer_text, ParagraphStyle('Footer', parent=styles['Normal'], alignment=TA_CENTER, textColor=colors.grey, fontSize=8)))

        doc.build(story)
        return filename