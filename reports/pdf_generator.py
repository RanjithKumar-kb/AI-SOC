import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

def generate_pdf_report():
    # Ensure reports directory exists
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    pdf_filename = f"security_incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    file_path = os.path.join(REPORTS_DIR, pdf_filename)
    
    doc = SimpleDocTemplate(file_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=12
    )
    story.append(Paragraph("🛡️ AI SOC Security Incident Report", title_style))
    story.append(Spacer(1, 10))
    
    # Report Metadata
    meta_text = f"<b>Generated At:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/><b>Status:</b> Critical Threat Inspection Completed"
    story.append(Paragraph(meta_text, styles['Normal']))
    story.append(Spacer(1, 15))
    
    # Summary Table
    data = [
        ["Category", "Details", "Action Taken"],
        ["Brute Force Attack", "Multiple SSH/Login failures detected", "Source IP Blocked"],
        ["SQL Injection", "Malicious SQL payloads in HTTP POST", "IP Flagged & Quarantined"],
    ]
    
    t = Table(data, colWidths=[150, 200, 150])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(t)
    
    doc.build(story)
    return file_path