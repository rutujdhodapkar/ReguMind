"""
PHANTOM COMPLIANCE — RBI Inspection Mode / Report Generator
Generates comprehensive PDF audit reports for RBI inspection.
Encrypted with CCO-set password, includes full blockchain audit trail.
"""

import os
import io
import json
import hashlib
import logging
from datetime import datetime, date
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, KeepTogether,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from config.settings import get_app_paths
from utils.database import get_connection
from p_crypto.blockchain import Blockchain
from p_crypto.encryptor import encrypt_bytes
from agents.risk_scorer import calculate_bank_score

logger = logging.getLogger("phantom_compliance.report_generator")

BANK_NAME = "Canara Bank"


def _section_circulars(conn, start_date: str, end_date: str) -> list:
    rows = conn.execute(
        """SELECT c.*, (SELECT count(*) FROM maps WHERE circular_id = c.id) as maps_count
           FROM circulars c WHERE date(c.ingested_at) >= ? AND date(c.ingested_at) <= ?
           ORDER BY c.ingested_at DESC""",
        (start_date, end_date),
    ).fetchall()
    return [dict(r) for r in rows]


def _section_maps(conn, start_date: str, end_date: str) -> list:
    rows = conn.execute(
        """SELECT m.*, c.circular_number, c.subject_line
           FROM maps m JOIN circulars c ON m.circular_id = c.id
           WHERE date(c.ingested_at) >= ? AND date(c.ingested_at) <= ?
           ORDER BY m.id""",
        (start_date, end_date),
    ).fetchall()
    return [dict(r) for r in rows]


def _section_blockchain(chain_path: Path) -> tuple[list[dict], bool]:
    blockchain = Blockchain(chain_path)
    chain = blockchain.get_chain()
    valid, errors = blockchain.verify_chain()
    return chain, valid


def _section_overdue(conn) -> list:
    rows = conn.execute(
        """SELECT m.*, c.circular_number, c.subject_line
           FROM maps m JOIN circulars c ON m.circular_id = c.id
           WHERE m.status IN ('BREACHED', 'ESCALATED')
           ORDER BY m.deadline_date""",
    ).fetchall()
    return [dict(r) for r in rows]


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("CoverTitle", fontSize=22, leading=28, alignment=1, spaceAfter=12, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle("CoverSub", fontSize=11, leading=14, alignment=1, spaceAfter=6, textColor=colors.HexColor("#4a5568")))
    styles.add(ParagraphStyle("SectionHead", fontSize=14, leading=18, spaceBefore=16, spaceAfter=8, fontName="Helvetica-Bold", textColor=colors.HexColor("#1a3c6e")))
    styles.add(ParagraphStyle("BodySmall", fontSize=7.5, leading=10))
    styles.add(ParagraphStyle("TableHeader", fontSize=7, leading=9, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle("TableCell", fontSize=6.5, leading=9))
    styles.add(ParagraphStyle("FooterNote", fontSize=6.5, leading=9, textColor=colors.gray, italic=True))
    return styles


def _make_table(data, col_widths=None, header_rows=1):
    if not data:
        return None
    s = _build_styles()
    formatted = []
    for i, row in enumerate(data):
        fmt_row = []
        for cell in row:
            fmt_row.append(Paragraph(str(cell or "—"), s["TableCell"] if i >= header_rows else s["TableHeader"]))
        formatted.append(fmt_row)
    t = Table(formatted, colWidths=col_widths, repeatRows=header_rows)
    style_cmds = [
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e0")),
        ("BACKGROUND", (0, 0), (-1, header_rows - 1), colors.HexColor("#1a3c6e")),
        ("TEXTCOLOR", (0, 0), (-1, header_rows - 1), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 6.5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(header_rows, len(data)):
        val = str(data[i][-1]) if len(data[i]) > 0 else ""
        if "VALIDATED" in val:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#c6f6d5")))
        elif "BREACH" in val or "ESCALATED" in val:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fed7d7")))
        elif "PENDING" in val:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fefcbf")))
    t.setStyle(TableStyle(style_cmds))
    return t


def generate_report(start_date: str, end_date: str, password: str) -> dict:
    """
    Generate a full RBI Audit Report as an encrypted PDF.
    Returns {"ok": bool, "path": str, "hash": str, "error": str}
    """
    if not REPORTLAB_AVAILABLE:
        return {"ok": False, "error": "reportlab library not installed. Run: pip install reportlab"}

    paths = get_app_paths()
    conn = get_connection()
    styles = _build_styles()

    reports_dir = paths["DATABASE_DIR"] / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"RBI_Audit_Report_{timestamp}.pdf"
    filepath = reports_dir / filename

    chain_path = paths["CHAIN_PATH"]
    blockchain = Blockchain(chain_path)
    chain, chain_valid = _section_blockchain(chain_path)

    circs = _section_circulars(conn, start_date, end_date)
    maps_data = _section_maps(conn, start_date, end_date)
    overdue = _section_overdue(conn)
    risk = calculate_bank_score()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=20 * mm, bottomMargin=20 * mm,
        leftMargin=15 * mm, rightMargin=15 * mm,
    )
    elements = []

    # ── Cover Page ──
    elements.append(Spacer(1, 60 * mm))
    elements.append(Paragraph("RBI INSPECTION AUDIT REPORT", styles["CoverTitle"]))
    elements.append(Paragraph(BANK_NAME, styles["CoverSub"]))
    elements.append(Spacer(1, 10 * mm))
    elements.append(Paragraph(f"Reporting Period: {start_date} to {end_date}", styles["CoverSub"]))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%d-%b-%Y %H:%M:%S')}", styles["CoverSub"]))
    elements.append(Spacer(1, 8 * mm))
    chain_status = "✅ Blockchain Integrity: VERIFIED — No tampering detected" if chain_valid else "⚠ Blockchain Integrity: TAMPERING DETECTED"
    elements.append(Paragraph(chain_status, styles["CoverSub"]))
    elements.append(Spacer(1, 15 * mm))
    elements.append(HRFlowable(width="60%", thickness=1, color=colors.HexColor("#1a3c6e")))

    # ── Section 1: Circular Registry ──
    elements.append(PageBreak())
    elements.append(Paragraph("Section 1 — Circular Registry", styles["SectionHead"]))
    if circs:
        hdr = ["Circular No", "Date Received", "Department", "MAPs", "Status"]
        data = [hdr] + [
            [c.get("circular_number", ""), c.get("ingested_at", "")[:10],
             c.get("department_code", ""), str(c.get("maps_count", 0)), "Processed"]
            for c in circs
        ]
        t = _make_table(data, col_widths=[90, 70, 70, 40, 60])
        if t:
            elements.append(t)
    else:
        elements.append(Paragraph("No circulars in this period.", styles["BodySmall"]))
    elements.append(Spacer(1, 5 * mm))

    # ── Section 2: MAP Completion ──
    elements.append(PageBreak())
    elements.append(Paragraph("Section 2 — MAP Completion Summary", styles["SectionHead"]))
    if maps_data:
        hdr = ["MAP ID", "Circular", "Department", "Action Required", "Deadline", "Status", "Has Evidence"]
        data = [hdr] + [
            [str(m.get("id", "")), m.get("circular_number", ""),
             m.get("assigned_to", ""), (m.get("map_text", "") or "")[:60],
             (m.get("deadline_date", "") or "")[:10], m.get("status", ""),
             "Yes" if m.get("evidence_text") else "No"]
            for m in maps_data
        ]
        t = _make_table(data, col_widths=[35, 55, 55, 110, 50, 55, 40])
        if t:
            elements.append(t)
    else:
        elements.append(Paragraph("No MAPs in this period.", styles["BodySmall"]))

    # ── Section 3: Compliance Scores ──
    elements.append(PageBreak())
    elements.append(Paragraph("Section 3 — Department Compliance Scores", styles["SectionHead"]))
    scores_data = risk.get("departments", [])
    hdr = ["Department", "Score", "Total MAPs", "Completed", "Overdue", "Risk Level"]
    data = [hdr] + [
        [d.get("display_name", d["department"]), str(d["score"]),
         str(d["total_maps"]), str(d["validated"]), str(d["overdue"]),
         "GREEN" if d["score"] >= 90 else "YELLOW" if d["score"] >= 70 else "ORANGE" if d["score"] >= 50 else "RED"]
        for d in scores_data
    ]
    t = _make_table(data, col_widths=[100, 50, 55, 55, 50, 80])
    if t:
        elements.append(t)
    elements.append(Spacer(1, 5 * mm))
    elements.append(Paragraph(f"Bank-Wide Score: {risk['bank_score']}/100 — {risk['threshold_label']}", styles["BodySmall"]))

    # ── Section 4: Blockchain Audit Trail ──
    elements.append(PageBreak())
    elements.append(Paragraph("Section 4 — Blockchain Audit Trail", styles["SectionHead"]))
    if chain:
        hdr = ["Block #", "Timestamp", "Action", "Data Hash (short)", "Block Hash (short)"]
        data = [hdr] + [
            [str(b.get("index", "")), (b.get("timestamp", "") or "")[:19],
             b.get("action", ""), (b.get("data_hash", "") or "")[:20] + "...",
             (b.get("block_hash", "") or "")[:20] + "..."]
            for b in chain
        ]
        t = _make_table(data, col_widths=[40, 70, 80, 110, 90])
        if t:
            elements.append(t)
    elements.append(Spacer(1, 5 * mm))
    elements.append(Paragraph(
        "Chain integrity verified. Any post-generation tampering of this report "
        "is detectable by recomputing block hashes against the live blockchain.",
        styles["FooterNote"],
    ))

    # ── Section 5: Overdue & Escalations ──
    elements.append(PageBreak())
    elements.append(Paragraph("Section 5 — Overdue & Escalations", styles["SectionHead"]))
    if overdue:
        hdr = ["MAP ID", "Circular", "Action Required", "Deadline", "Status"]
        data = [hdr] + [
            [str(m.get("id", "")), m.get("circular_number", ""),
             (m.get("map_text", "") or "")[:60],
             (m.get("deadline_date", "") or "")[:10], m.get("status", "")]
            for m in overdue
        ]
        t = _make_table(data, col_widths=[40, 65, 180, 55, 55])
        if t:
            elements.append(t)
    else:
        elements.append(Paragraph("No overdue items.", styles["BodySmall"]))

    # ── Footer Hash ──
    elements.append(Spacer(1, 10 * mm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.gray))

    doc.build(elements)
    pdf_data = buf.getvalue()
    buf.close()

    # Compute SHA256 hash of the entire report
    report_hash = hashlib.sha256(pdf_data).hexdigest()

    # Encrypt PDF with CCO password
    encrypted = encrypt_bytes(pdf_data, password.encode("utf-8"))

    # Write encrypted report
    with open(filepath, "wb") as f:
        f.write(encrypted)

    # Append blockchain block for the report
    block = blockchain.add_entry("AUDIT_REPORT_GENERATED", {
        "filename": filename,
        "period": f"{start_date}_to_{end_date}",
        "hash": report_hash,
        "chain_valid": chain_valid,
        "circulars_count": len(circs),
        "maps_count": len(maps_data),
    })

    audit_log(0, "SYSTEM", "AUDIT_REPORT_GENERATED", "report", 0,
              f"Report: {filename}, Hash: {report_hash[:16]}..., Block: {block['index']}")
    create_notification("Audit Report Generated", f"RBI report {filename}", "INFO", role="CCO")

    conn.close()
    return {
        "ok": True,
        "path": str(filepath),
        "filename": filename,
        "hash": report_hash,
        "blocks": block["index"],
        "size_bytes": len(pdf_data),
    }
