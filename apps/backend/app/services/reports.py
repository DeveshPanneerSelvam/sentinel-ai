from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import Alert


def render_incident_pdf(alert: Alert) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=letter, title=f"Incident Report {alert.id}")
    styles = getSampleStyleSheet()

    rows = [
        ["Severity", alert.severity],
        ["Risk score", f"{alert.risk_score:.1f}"],
        ["MITRE ATT&CK", f"{alert.mitre_technique_id} - {alert.mitre_technique_name}"],
        ["Category", alert.category],
        ["Source file", alert.source_file],
    ]
    table = Table(rows, colWidths=[120, 360])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    story = [
        Paragraph("SentinelAI Incident Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(alert.title, styles["Heading2"]),
        table,
        Spacer(1, 12),
        Paragraph("LLM Explanation", styles["Heading3"]),
        Paragraph(alert.explanation, styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Evidence", styles["Heading3"]),
        Paragraph(str(alert.evidence), styles["Code"]),
        Spacer(1, 12),
        Paragraph("Investigation Notes", styles["Heading3"]),
    ]
    if alert.notes:
        story.extend(Paragraph(note.body, styles["BodyText"]) for note in alert.notes)
    else:
        story.append(Paragraph("No notes recorded.", styles["BodyText"]))

    document.build(story)
    return buffer.getvalue()

