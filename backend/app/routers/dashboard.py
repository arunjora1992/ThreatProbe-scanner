"""Dashboard aggregate statistics."""
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import CVE, Finding, Host, Scan, Target, User, WebFinding

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
def stats(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    scan_status = dict(
        db.query(Scan.status, func.count(Scan.id)).group_by(Scan.status).all()
    )
    finding_sev = dict(
        db.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all()
    )
    web_sev = dict(
        db.query(WebFinding.severity, func.count(WebFinding.id)).group_by(WebFinding.severity).all()
    )
    # merge web severities into the overall severity picture
    combined = dict(finding_sev)
    for k, v in web_sev.items():
        combined[k] = combined.get(k, 0) + v

    recent = (
        db.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()
    )
    recent_out = [
        {
            "id": s.id, "target_id": s.target_id, "scan_type": s.scan_type,
            "status": s.status, "progress": s.progress,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "finding_count": db.query(Finding).filter(Finding.scan_id == s.id).count()
            + db.query(WebFinding).filter(WebFinding.scan_id == s.id).count(),
        }
        for s in recent
    ]

    return {
        "targets": db.query(Target).count(),
        "scans": db.query(Scan).count(),
        "hosts": db.query(Host).count(),
        "cves": db.query(CVE).count(),
        "findings_total": db.query(Finding).count() + db.query(WebFinding).count(),
        "scan_status": scan_status,
        "severity_breakdown": combined,
        "recent_scans": recent_out,
    }
