"""Report export endpoints: per-scan and filtered consolidated CSV/PDF."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import Scan, User
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
    fname = f"scan_{scan.id}_report.csv"
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
    fname = f"scan_{scan.id}_package_inventory.csv"
    return Response(
        content=data, media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/scan/{scan_id}/pdf")
def report_pdf(scan_id: int, db: Session = Depends(get_db),
               _: User = Depends(get_current_user)):
    scan = _get_scan(db, scan_id)
    data = build_findings_pdf(db, scan)
    fname = f"scan_{scan.id}_report.pdf"
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
