"""PDF report generation using reportlab (pure-Python, no system deps).

Produces an executive-style assessment report:
  - Title page with scan metadata
  - Executive summary with severity breakdown
  - Per-host service inventory
  - Detailed findings (vulnerability, CVSS, description, remediation, references)
"""
import io
from collections import Counter
from typing import List

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph as _RLParagraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from xml.sax.saxutils import escape as _xml_escape


def Paragraph(text, style):
    """Safe Paragraph: XML-escape dynamic text (CVE descriptions often contain
    '<', '>', '&' which crash reportlab's mini-markup parser), then restore only the
    handful of structural tags this module intentionally emits."""
    s = _xml_escape(str(text if text is not None else ""))
    for esc, raw in (("&lt;b&gt;", "<b>"), ("&lt;/b&gt;", "</b>"),
                     ("&lt;br/&gt;", "<br/>"), ("&amp;nbsp;", "&nbsp;")):
        s = s.replace(esc, raw)
    return _RLParagraph(s, style)
from sqlalchemy.orm import Session

from ..models import CVE, Finding, Host, Scan, Service, WebFinding

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#7e1416"),
    "HIGH": colors.HexColor("#c0392b"),
    "MEDIUM": colors.HexColor("#e67e22"),
    "LOW": colors.HexColor("#2980b9"),
    "NONE": colors.HexColor("#7f8c8d"),
    "UNKNOWN": colors.HexColor("#7f8c8d"),
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("Cell", parent=ss["Normal"], fontSize=8, leading=10))
    ss.add(ParagraphStyle("CellSmall", parent=ss["Normal"], fontSize=7, leading=9))
    ss.add(ParagraphStyle("H1c", parent=ss["Title"], fontSize=22, spaceAfter=6))
    ss.add(ParagraphStyle("Sub", parent=ss["Normal"], fontSize=11,
                          textColor=colors.HexColor("#555555")))
    return ss


def build_findings_pdf(db: Session, scan: Scan) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm,
        leftMargin=1.5 * cm, rightMargin=1.5 * cm,
        title=f"Vulnerability Assessment Report - Scan {scan.id}",
    )
    ss = _styles()
    story = []

    target = scan.target
    findings: List[Finding] = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    hosts: List[Host] = db.query(Host).filter(Host.scan_id == scan.id).all()

    # ---- Title ----
    story.append(Paragraph("Vulnerability Assessment Report", ss["H1c"]))
    story.append(Paragraph("Air-Gapped Penetration Testing Platform", ss["Sub"]))
    story.append(Spacer(1, 0.6 * cm))

    meta = [
        ["Target", f"{target.name} ({target.address})"],
        ["Scan ID", str(scan.id)],
        ["Scan type", scan.scan_type],
        ["nmap profile", scan.profile or "-"],
        ["Status", scan.status],
        ["Started", str(scan.started_at or "-")],
        ["Finished", str(scan.finished_at or "-")],
        ["Operator", scan.created_by or "-"],
        ["Hosts discovered", str(len(hosts))],
        ["Total findings", str(len(findings))],
    ]
    t = Table(meta, colWidths=[4 * cm, 13 * cm])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#333333")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, colors.HexColor("#fafbfc")]),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.6 * cm))

    # ---- Executive summary ----
    story.append(Paragraph("Executive Summary", ss["Heading2"]))
    counts = Counter(f.severity for f in findings)
    summary_rows = [["Severity", "Count"]]
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            summary_rows.append([sev, str(counts[sev])])
    if len(summary_rows) == 1:
        summary_rows.append(["No findings", "0"])
    st = Table(summary_rows, colWidths=[6 * cm, 4 * cm])
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]
    for i, row in enumerate(summary_rows[1:], start=1):
        c = SEVERITY_COLORS.get(row[0], colors.grey)
        style.append(("TEXTCOLOR", (0, i), (0, i), c))
        style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    st.setStyle(TableStyle(style))
    story.append(st)
    story.append(Spacer(1, 0.5 * cm))

    # ---- Host inventory ----
    story.append(Paragraph("Host & Service Inventory", ss["Heading2"]))
    inv_rows = [["Host", "Hostname", "OS", "Open services"]]
    for h in hosts:
        svcs = db.query(Service).filter(Service.host_id == h.id).all()
        svc_str = ", ".join(
            f"{s.port}/{s.protocol} {s.service_name}".strip() for s in svcs[:25]
        ) or "none"
        inv_rows.append([
            Paragraph(h.address, ss["CellSmall"]),
            Paragraph(h.hostname or "-", ss["CellSmall"]),
            Paragraph(h.os_guess or "-", ss["CellSmall"]),
            Paragraph(svc_str, ss["CellSmall"]),
        ])
    inv = Table(inv_rows, colWidths=[3 * cm, 3.5 * cm, 4 * cm, 6.5 * cm], repeatRows=1)
    inv.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafbfc")]),
    ]))
    story.append(inv)
    story.append(Spacer(1, 0.5 * cm))

    # ---- Detailed findings ----
    story.append(Paragraph("Detailed Findings", ss["Heading2"]))
    sev_weight = {s: i for i, s in enumerate(reversed(SEVERITY_ORDER))}
    findings.sort(key=lambda f: (sev_weight.get(f.severity, 0), f.cvss_score or 0), reverse=True)

    cve_cache = {}
    if not findings:
        story.append(Paragraph("No vulnerabilities were correlated for this scan.", ss["Normal"]))

    for f in findings:
        svc = db.get(Service, f.service_id)
        host = db.get(Host, svc.host_id) if svc else None
        if f.cve_id not in cve_cache:
            cve_cache[f.cve_id] = db.query(CVE).filter(CVE.cve_id == f.cve_id).first()
        cve: CVE = cve_cache[f.cve_id]

        sev_color = SEVERITY_COLORS.get(f.severity, colors.grey)
        header = Table(
            [[Paragraph(f"<b>{f.cve_id}</b> &nbsp; {f.severity} "
                        f"(CVSS {f.cvss_score if f.cvss_score is not None else 'N/A'})",
                        ss["Cell"])]],
            colWidths=[17 * cm],
        )
        header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_color),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(Spacer(1, 0.25 * cm))
        story.append(header)

        loc = (f"{host.address if host else '?'}:{svc.port if svc else '?'}/"
               f"{svc.protocol if svc else ''} "
               f"({svc.service_name if svc else ''} {svc.product if svc else ''} "
               f"{svc.version if svc else ''})".strip())
        detail_rows = [
            ["Affected asset", Paragraph(loc, ss["Cell"])],
            ["Status", Paragraph(f.status, ss["Cell"])],
            ["Match", Paragraph(f"{f.match_confidence} — {f.match_reason}", ss["Cell"])],
            ["CWE", Paragraph(cve.cwe if cve and cve.cwe else "-", ss["Cell"])],
            ["Description", Paragraph((cve.description if cve else "") or "-", ss["Cell"])],
            ["Remediation", Paragraph((cve.remediation if cve else "") or "-", ss["Cell"])],
        ]
        refs = (cve.references if cve else "") or ""
        if refs.strip():
            ref_html = "<br/>".join(refs.splitlines()[:6])
            detail_rows.append(["References", Paragraph(ref_html, ss["CellSmall"])])
        dt = Table(detail_rows, colWidths=[3 * cm, 14 * cm])
        dt.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e0e0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(dt)

    # ---- Web / URL penetration test findings ----
    web: List[WebFinding] = db.query(WebFinding).filter(WebFinding.scan_id == scan.id).all()
    if web:
        web.sort(key=lambda w: (sev_weight.get(w.severity, 0), w.cvss_score or 0), reverse=True)
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph("Web Application / URL Findings", ss["Heading2"]))
        for w in web:
            sev_color = SEVERITY_COLORS.get(w.severity, colors.grey)
            header = Table(
                [[Paragraph(f"<b>{w.name}</b> &nbsp; [{w.category}] &nbsp; {w.severity}",
                            ss["Cell"])]],
                colWidths=[17 * cm],
            )
            header.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), sev_color),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(Spacer(1, 0.25 * cm))
            story.append(header)
            rows = [
                ["Target", Paragraph(w.target_url or "-", ss["Cell"])],
                ["Status", Paragraph(w.status, ss["Cell"])],
                ["Description", Paragraph(w.description or "-", ss["Cell"])],
                ["Evidence", Paragraph(w.evidence or "-", ss["CellSmall"])],
                ["Remediation", Paragraph(w.remediation or "-", ss["Cell"])],
            ]
            if w.cve_id:
                rows.insert(2, ["CVE", Paragraph(w.cve_id, ss["Cell"])])
            if (w.references or "").strip():
                rows.append(["References",
                             Paragraph("<br/>".join(w.references.splitlines()[:6]), ss["CellSmall"])])
            dt = Table(rows, colWidths=[3 * cm, 14 * cm])
            dt.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e0e0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(dt)

    doc.build(story)
    return buf.getvalue()


def build_consolidated_pdf(data: dict) -> bytes:
    """Render a filtered, multi-scan report (from report_query.collect_report_rows) to PDF."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm,
        leftMargin=1.5 * cm, rightMargin=1.5 * cm,
        title="Consolidated Vulnerability Report",
    )
    ss = _styles()
    story = []
    meta = data.get("meta", {})
    filters = meta.get("filters", {})
    counts = meta.get("counts", {})

    story.append(Paragraph("Consolidated Vulnerability Report", ss["H1c"]))
    story.append(Paragraph("Air-Gapped Penetration Testing Platform", ss["Sub"]))
    story.append(Spacer(1, 0.5 * cm))

    # ---- Filter / scope summary ----
    story.append(Paragraph("Report scope & filters", ss["Heading2"]))
    def _fmt(v):
        return ", ".join(v) if isinstance(v, list) else str(v)
    frows = [
        ["Scope", _fmt(filters.get("target", "-"))],
        ["Finding types", _fmt(filters.get("types", "-"))],
        ["Severities", _fmt(filters.get("severities", "-"))],
        ["Statuses", _fmt(filters.get("statuses", "-"))],
        ["Match confidence", _fmt(filters.get("confidences", "-"))],
        ["Host filter", _fmt(filters.get("host", "-"))],
        ["Port filter", _fmt(filters.get("port", "-"))],
        ["CVE filter", _fmt(filters.get("cve_id", "-"))],
        ["Package filter", _fmt(filters.get("package", "-"))],
        ["Vulnerable packages only", _fmt(filters.get("vulnerable_only", False))],
        ["Total findings", str(counts.get("total", 0))],
    ]
    t = Table(frows, colWidths=[5 * cm, 12 * cm])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))

    # ---- Executive severity breakdown ----
    story.append(Paragraph("Executive Summary", ss["Heading2"]))
    bd = meta.get("severity_breakdown", {})
    srows = [["Severity", "Count"]]
    for sev in SEVERITY_ORDER + ["INFO"]:
        if bd.get(sev):
            srows.append([sev, str(bd[sev])])
    if len(srows) == 1:
        srows.append(["No findings", "0"])
    st = Table(srows, colWidths=[6 * cm, 4 * cm])
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]
    for i, row in enumerate(srows[1:], start=1):
        style.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS.get(row[0], colors.grey)))
        style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    st.setStyle(TableStyle(style))
    story.append(st)

    def _finding_block(title_text, severity, rows):
        sev_color = SEVERITY_COLORS.get(severity, colors.grey)
        header = Table([[Paragraph(title_text, ss["Cell"])]], colWidths=[17 * cm])
        header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_color),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(Spacer(1, 0.22 * cm))
        story.append(header)
        dt = Table(rows, colWidths=[3 * cm, 14 * cm])
        dt.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e0e0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(dt)

    # Cap detailed blocks per section so a huge result set can't OOM/timeout the PDF.
    MAX_DETAIL = 400

    def _truncnote(n):
        if n > MAX_DETAIL:
            story.append(Paragraph(
                f"Showing the {MAX_DETAIL} highest-severity of {n} findings — "
                f"use the CSV export or tighten filters for the full list.", ss["Sub"]))

    # ---- Server / CVE findings ----
    if data.get("cve"):
        story.append(Paragraph(f"Server / Network CVE Findings ({len(data['cve'])})", ss["Heading2"]))
        _truncnote(len(data["cve"]))
        for r in data["cve"][:MAX_DETAIL]:
            _finding_block(
                f"<b>{r['cve_id']}</b> &nbsp; {r['severity']} (CVSS {r['cvss'] if r['cvss'] is not None else 'N/A'})",
                r["severity"],
                [
                    ["Scan / target", Paragraph(f"#{r['scan_id']} — {r['target']}", ss["Cell"])],
                    ["Asset", Paragraph(f"{r['host']}:{r['port']}/{r['protocol']} ({r['service']} {r['product']} {r['version']})", ss["Cell"])],
                    ["Status / match", Paragraph(f"{r['status']} · {r['confidence']} — {r['match_reason']}", ss["Cell"])],
                    ["Description", Paragraph(r["description"] or "-", ss["Cell"])],
                    ["Remediation", Paragraph(r["remediation"] or "-", ss["Cell"])],
                ],
            )

    # ---- Web findings ----
    if data.get("web"):
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph(f"Web / URL Findings ({len(data['web'])})", ss["Heading2"]))
        _truncnote(len(data["web"]))
        for r in data["web"][:MAX_DETAIL]:
            _finding_block(
                f"<b>{r['name']}</b> &nbsp; [{r['category']}] &nbsp; {r['severity']}",
                r["severity"],
                [
                    ["Scan / target", Paragraph(f"#{r['scan_id']} — {r['target']}", ss["Cell"])],
                    ["Target URL", Paragraph(r["target_url"] or "-", ss["Cell"])],
                    ["Status", Paragraph(r["status"], ss["Cell"])],
                    ["Description", Paragraph(r["description"] or "-", ss["Cell"])],
                    ["Evidence", Paragraph(r["evidence"] or "-", ss["CellSmall"])],
                    ["Remediation", Paragraph(r["remediation"] or "-", ss["Cell"])],
                ],
            )

    # ---- Package findings ----
    if data.get("package"):
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph(f"Package Inventory Findings ({len(data['package'])})", ss["Heading2"]))
        _truncnote(len(data["package"]))
        for r in data["package"][:MAX_DETAIL]:
            _finding_block(
                f"<b>{r['name']}</b> {r['full_version'] or r['version']} &nbsp; {r['severity']} ({r['cve_count']} CVE)",
                r["severity"],
                [
                    ["Scan / target", Paragraph(f"#{r['scan_id']} — {r['target']}", ss["Cell"])],
                    ["Status", Paragraph(r["status"], ss["Cell"])],
                    ["CVEs", Paragraph(r["cve_ids"] or "-", ss["CellSmall"])],
                    ["Patching remedy", Paragraph(r["remediation"] or "-", ss["Cell"])],
                ],
            )

    if not (data.get("cve") or data.get("web") or data.get("package")):
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph("No findings match the selected filters.", ss["Normal"]))

    doc.build(story)
    return buf.getvalue()
