"""
PDF Exporter — renders a structured report dict into a PDF document.
Uses ReportLab for full offline PDF generation.
"""
from __future__ import annotations
import io
from pathlib import Path
from typing import Optional
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ── Color palette ──────────────────────────────────────────────────────────────
DARK_BG = colors.HexColor("#0F172A")
ACCENT = colors.HexColor("#3B82F6")
ACCENT_LIGHT = colors.HexColor("#EFF6FF")
TEXT_DARK = colors.HexColor("#1E293B")
TEXT_GRAY = colors.HexColor("#64748B")
RED = colors.HexColor("#EF4444")
GREEN = colors.HexColor("#22C55E")
YELLOW = colors.HexColor("#F59E0B")
WHITE = colors.white


def _get_styles():
    styles = getSampleStyleSheet()
    custom = {
        "Title": ParagraphStyle("Title", parent=styles["Normal"], fontSize=22, textColor=WHITE,
                                fontName="Helvetica-Bold", spaceAfter=6, leading=28),
        "Subtitle": ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=11, textColor=colors.HexColor("#94A3B8"),
                                   fontName="Helvetica", spaceAfter=4),
        "H2": ParagraphStyle("H2", parent=styles["Normal"], fontSize=14, textColor=TEXT_DARK,
                              fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6),
        "H3": ParagraphStyle("H3", parent=styles["Normal"], fontSize=11, textColor=ACCENT,
                              fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4),
        "Body": ParagraphStyle("Body", parent=styles["Normal"], fontSize=9, textColor=TEXT_DARK,
                               fontName="Helvetica", leading=13, spaceAfter=4),
        "BodySmall": ParagraphStyle("BodySmall", parent=styles["Normal"], fontSize=8, textColor=TEXT_GRAY,
                                    fontName="Helvetica", leading=11),
        "Code": ParagraphStyle("Code", parent=styles["Normal"], fontSize=7.5, textColor=TEXT_DARK,
                               fontName="Courier", leading=10, backColor=colors.HexColor("#F8FAFC"),
                               leftIndent=8, rightIndent=8, spaceBefore=2, spaceAfter=2),
    }
    return custom


def _table_style(header_color=ACCENT) -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_color),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, colors.HexColor("#F1F5F9")]),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 7.5),
        ("TOPPADDING", (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ])


def export_to_pdf(report: dict, output_path: Optional[str] = None) -> bytes:
    """
    Generate a PDF from the report dict.
    Returns PDF bytes. If output_path is given, also saves to file.
    """
    styles = _get_styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=15 * mm, bottomMargin=20 * mm,
    )

    story = []
    page_width = A4[0] - 40 * mm

    # ── Cover header ──────────────────────────────────────────────────────────
    header_data = [[
        Paragraph("CONVERSATIONAL SIEM ASSISTANT", styles["Title"]),
        Paragraph("INCIDENT REPORT", styles["Title"]),
    ]]
    header_table = Table(header_data, colWidths=[page_width * 0.6, page_width * 0.4])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK_BG),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8))

    inv = report.get("investigation", {})
    story.append(Paragraph(inv.get("title", "Security Investigation"), styles["H2"]))
    story.append(Paragraph(
        f"Generated: {report.get('generated_at', '')[:19].replace('T', ' ')} UTC  |  "
        f"Analyst: {report.get('analyst', 'SOC Analyst')}  |  "
        f"Investigation ID: {str(report.get('investigation_id', ''))[:8]}",
        styles["BodySmall"]
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=10))

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", styles["H2"]))
    exec_text = report.get("executive_summary", "")
    for para in exec_text.split("\n\n"):
        if para.strip():
            story.append(Paragraph(para.strip(), styles["Body"]))
    story.append(Spacer(1, 6))

    # ── Investigation Details ─────────────────────────────────────────────────
    story.append(Paragraph("Investigation Details", styles["H2"]))
    det_data = [
        ["Analyst Query", inv.get("analyst_query", "")],
        ["Total Events Matched", str(inv.get("total_events_matched", 0))],
        ["Events Analyzed", str(inv.get("events_analyzed", 0))],
        ["Time Range (From)", str(inv.get("time_range", {}).get("from", "N/A") or "N/A")[:30]],
        ["Time Range (To)", str(inv.get("time_range", {}).get("to", "N/A") or "N/A")[:30]],
    ]
    det_table = Table(det_data, colWidths=[page_width * 0.3, page_width * 0.7])
    det_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (0, 0), (0, -1), ACCENT_LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(det_table)
    story.append(Spacer(1, 8))

    # ── IOC Table ─────────────────────────────────────────────────────────────
    iocs = report.get("iocs", [])
    if iocs:
        story.append(Paragraph("Extracted Indicators of Compromise (IOCs)", styles["H2"]))
        ioc_table_data = [["Type", "Value", "Occurrences", "Internal?"]]
        for ioc in iocs[:30]:
            ioc_table_data.append([
                ioc.get("type", ""),
                str(ioc.get("value", ""))[:60],
                str(ioc.get("occurrence_count", 1)),
                "Yes" if ioc.get("is_internal") else "No" if "is_internal" in ioc else "N/A",
            ])
        ioc_tbl = Table(ioc_table_data, colWidths=[
            page_width * 0.15, page_width * 0.55, page_width * 0.15, page_width * 0.15
        ])
        ioc_tbl.setStyle(_table_style(RED))
        story.append(ioc_tbl)
        story.append(Spacer(1, 8))

    # ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────
    mitre_techniques = report.get("attack_analysis", {}).get("mitre_techniques", [])
    if mitre_techniques:
        story.append(Paragraph("MITRE ATT&CK Technique Mapping", styles["H2"]))
        mitre_data = [["Technique ID", "Technique Name", "Tactic", "Confidence", "Evidence"]]
        for m in mitre_techniques:
            mitre_data.append([
                m.get("technique_id", ""),
                m.get("technique_name", ""),
                m.get("tactic", ""),
                f"{m.get('confidence', 0):.0%}",
                str(m.get("evidence_count", "")),
            ])
        mitre_tbl = Table(mitre_data, colWidths=[
            page_width * 0.14, page_width * 0.28, page_width * 0.28, page_width * 0.15, page_width * 0.15
        ])
        mitre_tbl.setStyle(_table_style(colors.HexColor("#7C3AED")))
        story.append(mitre_tbl)
        story.append(Spacer(1, 8))

    # ── Attack Timeline ───────────────────────────────────────────────────────
    tl_events = report.get("timeline", {}).get("events", [])
    if tl_events:
        story.append(Paragraph("Attack Timeline", styles["H2"]))
        tl_data = [["Timestamp (UTC)", "Phase", "Source IP", "Event", "Description"]]
        for evt in tl_events[:40]:
            tl_data.append([
                str(evt.get("timestamp", ""))[:19].replace("T", " "),
                evt.get("phase", "").replace("_", " ").title(),
                evt.get("source_ip", ""),
                evt.get("event_action", "").replace("_", " "),
                str(evt.get("description", ""))[:55],
            ])
        tl_tbl = Table(tl_data, colWidths=[
            page_width * 0.19, page_width * 0.14, page_width * 0.14, page_width * 0.15, page_width * 0.38
        ])
        tl_tbl.setStyle(_table_style(colors.HexColor("#0F766E")))
        story.append(tl_tbl)
        story.append(Spacer(1, 8))

    # ── Evidence Sample ───────────────────────────────────────────────────────
    evidence = report.get("evidence", [])
    if evidence:
        story.append(PageBreak())
        story.append(Paragraph("Evidence — Security Log Entries", styles["H2"]))
        ev_data = [["Log ID", "Timestamp", "Source IP", "Username", "Action", "HTTP", "URL"]]
        for ev in evidence[:25]:
            ev_data.append([
                str(ev.get("log_id", ""))[:8],
                str(ev.get("timestamp", ""))[:16].replace("T", " "),
                ev.get("source_ip", ""),
                ev.get("username", ""),
                ev.get("event_action", "").replace("_", " "),
                str(ev.get("http_status", "")),
                str(ev.get("url", ""))[:35],
            ])
        ev_tbl = Table(ev_data, colWidths=[
            page_width * 0.09, page_width * 0.15, page_width * 0.14,
            page_width * 0.12, page_width * 0.14, page_width * 0.07, page_width * 0.29
        ])
        ev_tbl.setStyle(_table_style())
        story.append(ev_tbl)
        story.append(Spacer(1, 8))

    # ── AI Explanation ────────────────────────────────────────────────────────
    explanation = report.get("explanation", "")
    if explanation:
        story.append(Paragraph("AI-Generated Analysis & Explanation", styles["H2"]))
        for para in explanation.split("\n\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), styles["Body"]))
        story.append(Spacer(1, 6))

    # ── Recommendations ───────────────────────────────────────────────────────
    recs = report.get("recommendations", [])
    if recs:
        story.append(Paragraph("Recommended Actions", styles["H2"]))
        for i, rec in enumerate(recs, 1):
            story.append(Paragraph(f"{i}. {rec}", styles["Body"]))
        story.append(Spacer(1, 6))

    # ── Footer note ───────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=TEXT_GRAY, spaceBefore=10, spaceAfter=6))
    story.append(Paragraph(
        "This report was generated by the Conversational SIEM Assistant. "
        "All findings are backed by retrieved log evidence. "
        "Confidence scores represent AI assessments and should be reviewed by a qualified analyst.",
        styles["BodySmall"]
    ))

    doc.build(story)

    pdf_bytes = buffer.getvalue()
    buffer.close()

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes
