"""Dashboard aggregate statistics."""
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import CVE, ConfigFinding, Finding, Host, Scan, Service, Target, User, WebFinding

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
            + db.query(WebFinding).filter(WebFinding.scan_id == s.id).count()
            + db.query(ConfigFinding).filter(ConfigFinding.scan_id == s.id,
                                             ConfigFinding.status == "fail").count(),
        }
        for s in recent
    ]

    # Threat-intel highlights: findings whose CVE is actively exploited (CISA KEV).
    kev_findings = (db.query(Finding).join(CVE, CVE.cve_id == Finding.cve_id)
                    .filter(CVE.kev.is_(True)).count())
    crit_high_open = (db.query(Finding)
                      .filter(Finding.severity.in_(["CRITICAL", "HIGH"]))
                      .filter(Finding.status == "open").count())

    # Top priorities: rank findings by exploited (KEV) -> EPSS -> CVSS.
    top_rows = (db.query(Finding, CVE, Service)
                .join(CVE, CVE.cve_id == Finding.cve_id)
                .outerjoin(Service, Service.id == Finding.service_id)
                .order_by(CVE.kev.desc(), CVE.epss_score.desc().nullslast(),
                          Finding.cvss_score.desc().nullslast())
                .limit(6).all())
    top_risk = [
        {
            "scan_id": f.scan_id, "cve_id": f.cve_id, "severity": f.severity,
            "cvss": f.cvss_score, "kev": bool(c.kev),
            "epss": c.epss_score,
            "package": (svc.product or svc.service_name) if svc else "",
        }
        for f, c, svc in top_rows
    ]

    return {
        "targets": db.query(Target).count(),
        "scans": db.query(Scan).count(),
        "hosts": db.query(Host).count(),
        "cves": db.query(CVE).count(),
        "findings_total": db.query(Finding).count() + db.query(WebFinding).count(),
        "kev_findings": kev_findings,
        "crit_high_open": crit_high_open,
        "scan_status": scan_status,
        "severity_breakdown": combined,
        "top_risk": top_risk,
        "recent_scans": recent_out,
    }
