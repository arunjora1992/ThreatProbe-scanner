"""Report export endpoints: per-scan and filtered consolidated CSV/PDF."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from sqlalchemy import func

from ..auth import get_current_user
from ..database import get_db
from ..models import Finding, Package, Scan, User, WebFinding
from ..schemas import EmailReportRequest
from ..services import mailer
from ..services.report_csv import (
    build_consolidated_csv,
    build_findings_csv,
    build_packages_csv,
)
from ..services.report_pdf import build_consolidated_pdf, build_findings_pdf
from ..services.report_query import collect_report_rows

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _get_scan(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _slug(text: str) -> str:
    """Filesystem-safe token from a target name/address."""
    import re
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", (text or "").strip()).strip("-")
    return s[:40] or "target"


def _report_basename(scan: Scan, suffix: str = "report") -> str:
    """e.g. webserver-prod_cis_benchmark_scan42_report — target name + scan type + id."""
    t = scan.target
    tgt = (t.name or t.address) if t else ""
    ts = scan.finished_at or scan.created_at
    stamp = ts.strftime("%Y%m%d-%H%M") if ts else ""
    parts = [_slug(tgt), scan.scan_type, f"scan{scan.id}"]
    if stamp:
        parts.append(stamp)
    parts.append(suffix)
    return "_".join(parts)


def _csv(values: Optional[str]):
    """Split a comma-separated query param into a list (or None)."""
    if not values:
        return None
    return [v for v in (x.strip() for x in values.split(",")) if v]


def _collect(db, target_id, severity, status, types, host, port, cve_id, package,
             confidence, vulnerable_only):
    return collect_report_rows(
        db, target_id=target_id,
        severities=_csv(severity), statuses=_csv(status), types=_csv(types),
        host=host or None, port=port, cve_id=cve_id or None, package=package or None,
        confidences=_csv(confidence), vulnerable_only=vulnerable_only,
    )


@router.get("/scan/{scan_id}/csv")
def report_csv(scan_id: int, db: Session = Depends(get_db),
               _: User = Depends(get_current_user)):
    scan = _get_scan(db, scan_id)
    data = build_findings_csv(db, scan)
    fname = f"{_report_basename(scan)}.csv"
    return Response(
        content=data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/scan/{scan_id}/packages.csv")
def report_packages_csv(scan_id: int, db: Session = Depends(get_db),
                        _: User = Depends(get_current_user)):
    scan = _get_scan(db, scan_id)
    data = build_packages_csv(db, scan)
    fname = f"{_report_basename(scan, 'package_inventory')}.csv"
    return Response(
        content=data, media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/scan/{scan_id}/pdf")
def report_pdf(scan_id: int, db: Session = Depends(get_db),
               _: User = Depends(get_current_user)):
    scan = _get_scan(db, scan_id)
    data = build_findings_pdf(db, scan)
    fname = f"{_report_basename(scan)}.pdf"
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ---- Filtered, consolidated (cross-scan) export ----
@router.get("/export.csv")
def export_csv(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    target_id: Optional[int] = None,
    severity: Optional[str] = Query(None, description="comma list e.g. CRITICAL,HIGH"),
    status: Optional[str] = Query(None, description="comma list of triage statuses"),
    types: Optional[str] = Query(None, description="comma list of cve,web,package"),
    host: Optional[str] = None,
    port: Optional[int] = None,
    cve_id: Optional[str] = None,
    package: Optional[str] = None,
    confidence: Optional[str] = Query(None, description="comma list high,medium,low"),
    vulnerable_only: bool = False,
):
    data = _collect(db, target_id, severity, status, types, host, port, cve_id,
                    package, confidence, vulnerable_only)
    return Response(
        content=build_consolidated_csv(data), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="vulnerability_report.csv"'},
    )


@router.get("/export.pdf")
def export_pdf(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    target_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    types: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    cve_id: Optional[str] = None,
    package: Optional[str] = None,
    confidence: Optional[str] = None,
    vulnerable_only: bool = False,
):
    data = _collect(db, target_id, severity, status, types, host, port, cve_id,
                    package, confidence, vulnerable_only)
    return Response(
        content=build_consolidated_pdf(data), media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="vulnerability_report.pdf"'},
    )


@router.get("/export/preview")
def export_preview(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    target_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    types: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    cve_id: Optional[str] = None,
    package: Optional[str] = None,
    confidence: Optional[str] = None,
    vulnerable_only: bool = False,
):
    """Return just the counts/breakdown for the current filters (live preview in the GUI)."""
    data = _collect(db, target_id, severity, status, types, host, port, cve_id,
                    package, confidence, vulnerable_only)
    return data["meta"]


def _scan_severity_counts(db: Session, scan_id: int) -> dict:
    counts = {}
    for sev, n in db.query(Finding.severity, func.count(Finding.id)).filter(
            Finding.scan_id == scan_id).group_by(Finding.severity).all():
        counts[sev] = counts.get(sev, 0) + n
    for sev, n in db.query(WebFinding.severity, func.count(WebFinding.id)).filter(
            WebFinding.scan_id == scan_id).group_by(WebFinding.severity).all():
        counts[sev] = counts.get(sev, 0) + n
    return counts


@router.post("/scan/{scan_id}/email")
def email_scan_report(scan_id: int, payload: EmailReportRequest,
                      db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Email a scan's report (PDF/CSV attached) with the severity counts in the body."""
    scan = _get_scan(db, scan_id)
    cfg = mailer.get_config(db)
    if not cfg or not cfg.host:
        raise HTTPException(status_code=400, detail="SMTP is not configured (Settings → Email)")

    recipients = [r.strip() for r in
                  (payload.recipients or cfg.default_recipients or "").split(",") if r.strip()]
    if not recipients:
        raise HTTPException(status_code=400, detail="No recipients specified")

    counts = _scan_severity_counts(db, scan_id)
    total = sum(counts.values())
    pkg_vuln = db.query(func.count(Package.id)).filter(
        Package.scan_id == scan_id, Package.status == "vulnerable").scalar() or 0
    target = scan.target

    body = (
        f"ThreatProbe Scanner — scan report\n"
        f"{'='*40}\n"
        f"Scan ID:    #{scan.id}\n"
        f"Target:     {target.name} ({target.address})\n"
        f"Scan type:  {scan.scan_type}\n"
        f"Status:     {scan.status}\n"
        f"Finished:   {scan.finished_at or '-'}\n\n"
        f"Total findings: {total}\n"
        f"Vulnerable packages: {pkg_vuln}\n\n"
        f"Severity breakdown:\n{mailer.severity_summary(counts)}\n\n"
        f"Full details are in the attached report(s).\n"
    )

    attachments = []
    if "pdf" in payload.formats:
        attachments.append((f"scan_{scan.id}_report.pdf", build_findings_pdf(db, scan), "pdf"))
    if "csv" in payload.formats:
        attachments.append((f"scan_{scan.id}_report.csv",
                            build_findings_csv(db, scan).encode("utf-8"), "csv"))

    try:
        mailer.send_email(cfg, recipients,
                          subject=f"[ThreatProbe] Scan #{scan.id} — {target.name} ({total} findings)",
                          body=body, attachments=attachments)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Email failed: {exc}")
    return {"sent": True, "recipients": recipients, "total_findings": total}


@router.get("/export/results")
def export_results(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    target_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    types: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    cve_id: Optional[str] = None,
    package: Optional[str] = None,
    confidence: Optional[str] = None,
    vulnerable_only: bool = False,
    limit: int = 1000,
):
    """Counts/breakdown PLUS the matching findings (capped) so the GUI can show the
    actual filtered list, not just a count."""
    data = _collect(db, target_id, severity, status, types, host, port, cve_id,
                    package, confidence, vulnerable_only)
    rows = []
    for r in data["cve"]:
        rows.append({"type": "CVE", "severity": r["severity"], "cvss": r["cvss"],
                     "target": r["target"], "location": f"{r['host']}:{r['port']}/{r['protocol']}",
                     "name": r["cve_id"], "detail": r["match_reason"],
                     "status": r["status"], "remediation": r["remediation"]})
    for r in data["web"]:
        rows.append({"type": "Web", "severity": r["severity"], "cvss": r["cvss"],
                     "target": r["target"], "location": r["target_url"],
                     "name": r["name"], "detail": (r["description"] or "")[:160],
                     "status": r["status"], "remediation": r["remediation"]})
    for r in data["package"]:
        rows.append({"type": "Package", "severity": r["severity"], "cvss": r["cvss"],
                     "target": r["target"],
                     "location": f"{r['name']} {r['full_version'] or r['version']}",
                     "name": r["cve_ids"] or r["name"], "detail": f"{r['cve_count']} CVE(s)",
                     "status": "vulnerable", "remediation": r["remediation"]})
    sev = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    rows.sort(key=lambda x: (sev.get(x["severity"], 0), x["cvss"] or 0), reverse=True)
    return {"meta": data["meta"], "rows": rows[:limit],
            "truncated": len(rows) > limit, "shown": min(len(rows), limit)}
