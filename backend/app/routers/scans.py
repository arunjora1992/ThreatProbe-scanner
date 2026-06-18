"""Scan lifecycle endpoints: queue a scan, list, inspect results, delete."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import Finding, Host, Package, Scan, Service, Target, User, WebFinding
from ..schemas import (
    FindingOut,
    HostOut,
    ScanCreate,
    ScanDetail,
    ScanOut,
)
from ..services.credentialed import start_credentialed_scan
from ..services.zap_runner import start_zap_bg_scan
from ..services.zap_scanner import ZapAuth

router = APIRouter(prefix="/api/scans", tags=["scans"])

VALID_TYPES = {"discovery", "port", "full", "web", "custom", "credentialed",
               "zap_passive", "zap_active"}


@router.get("", response_model=list[ScanOut])
def list_scans(target_id: int | None = None, db: Session = Depends(get_db),
               _: User = Depends(get_current_user)):
    q = db.query(Scan)
    if target_id is not None:
        q = q.filter(Scan.target_id == target_id)
    return q.order_by(Scan.created_at.desc()).all()


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    if user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot launch scans")
    if payload.scan_type not in VALID_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid scan_type. One of {VALID_TYPES}")
    target = db.get(Target, payload.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Credentialed (SSH) scans run in the backend, not the DB worker, so the
    # supplied credentials are never written to the database.
    if payload.scan_type == "credentialed":
        if not payload.ssh_username or not (payload.ssh_password or payload.ssh_key):
            raise HTTPException(
                status_code=400,
                detail="Credentialed scans require ssh_username and ssh_password or ssh_key",
            )
        scan = Scan(
            target_id=target.id, scan_type="credentialed",
            status="running",  # claimed immediately so the DB worker never picks it up
            created_by=user.username,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        start_credentialed_scan(
            scan_id=scan.id, address=target.address, port=payload.ssh_port,
            username=payload.ssh_username, password=payload.ssh_password,
            key_text=payload.ssh_key, key_passphrase=payload.ssh_key_passphrase,
        )
        return scan

    # ZAP scans that need authentication and/or the browser-driven AJAX spider run in
    # the backend (like credentialed SSH) so any supplied web-app login credentials are
    # never written to the database. Plain unauthenticated, non-AJAX scans fall through
    # to the DB worker below.
    if payload.scan_type in ("zap_passive", "zap_active") and (
            payload.zap_username or payload.zap_ajax_spider):
        auth = None
        if payload.zap_username:
            auth = ZapAuth(
                auth_type=(payload.zap_auth_type or "form").lower(),
                username=payload.zap_username,
                password=payload.zap_password or "",
                login_url=payload.zap_login_url or "",
                username_field=payload.zap_username_field or "username",
                password_field=payload.zap_password_field or "password",
                extra_post_data=payload.zap_extra_post_data or "",
                logged_in_regex=payload.zap_logged_in_regex or "",
                logged_out_regex=payload.zap_logged_out_regex or "",
                session=(payload.zap_session or "cookie").lower(),
                token_field=payload.zap_token_field or "token",
                session_headers=payload.zap_session_headers or "",
            )
            if not auth.configured():
                raise HTTPException(
                    status_code=400,
                    detail="Authenticated ZAP scans require a username, and (for form/json "
                           "auth) a login URL.",
                )
        scan = Scan(
            target_id=target.id, scan_type=payload.scan_type,
            status="running",  # claimed immediately so the DB worker never picks it up
            created_by=user.username,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        start_zap_bg_scan(scan_id=scan.id, active=(payload.scan_type == "zap_active"),
                          auth=auth, ajax=bool(payload.zap_ajax_spider))
        return scan

    scan = Scan(
        target_id=target.id,
        scan_type=payload.scan_type,
        # stash custom flags in profile so the worker can read them
        profile=(payload.custom_flags or "") if payload.scan_type == "custom" else "",
        status="queued",
        created_by=user.username,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_db),
             _: User = Depends(get_current_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    hosts = []
    for h in db.query(Host).filter(Host.scan_id == scan.id).all():
        svcs = db.query(Service).filter(Service.host_id == h.id).all()
        ho = HostOut.model_validate(h)
        ho.services = [s for s in svcs]
        hosts.append(ho)
    detail = ScanDetail.model_validate(scan)
    detail.hosts = hosts
    detail.finding_count = db.query(Finding).filter(Finding.scan_id == scan.id).count()
    return detail


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
def scan_findings(scan_id: int, severity: str | None = None, db: Session = Depends(get_db),
                  _: User = Depends(get_current_user)):
    if not db.get(Scan, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    q = db.query(Finding).filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity.upper())
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    findings = q.all()
    findings.sort(key=lambda f: (sev_order.get(f.severity, 0), f.cvss_score or 0), reverse=True)
    return findings


@router.get("/{scan_id}/web-findings")
def scan_web_findings(scan_id: int, db: Session = Depends(get_db),
                      _: User = Depends(get_current_user)):
    if not db.get(Scan, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    rows = db.query(WebFinding).filter(WebFinding.scan_id == scan_id).all()
    sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    rows.sort(key=lambda r: (sev_order.get(r.severity, 0), r.cvss_score or 0), reverse=True)
    return [
        {
            "id": r.id, "category": r.category, "name": r.name, "severity": r.severity,
            "cvss_score": r.cvss_score, "cve_id": r.cve_id, "description": r.description,
            "evidence": r.evidence, "remediation": r.remediation,
            "references": r.references, "status": r.status, "target_url": r.target_url,
        }
        for r in rows
    ]


@router.get("/{scan_id}/log")
def scan_log(scan_id: int, offset: int = 0, db: Session = Depends(get_db),
             _: User = Depends(get_current_user)):
    """Return the live scan log from a character offset (for the terminal-style view)."""
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    log = scan.log or ""
    return {"offset": len(log), "chunk": log[offset:] if offset < len(log) else "",
            "status": scan.status, "progress": scan.progress}


@router.get("/{scan_id}/packages")
def scan_packages(scan_id: int, only_vulnerable: bool = False, q: str | None = None,
                  db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Full installed-package inventory for a credentialed scan, with CVE/criticality/remedy."""
    if not db.get(Scan, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    query = db.query(Package).filter(Package.scan_id == scan_id)
    if only_vulnerable:
        query = query.filter(Package.status == "vulnerable")
    if q:
        query = query.filter(Package.name.ilike(f"%{q}%"))
    rows = query.all()
    sev = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1}
    rows.sort(key=lambda p: (sev.get(p.max_severity, 0), p.max_cvss or 0, p.name), reverse=True)
    return {
        "total": len(rows),
        "vulnerable": sum(1 for p in rows if p.status == "vulnerable"),
        "packages": [
            {
                "name": p.name, "version": p.version, "full_version": p.full_version,
                "manager": p.manager, "status": p.status, "max_severity": p.max_severity,
                "max_cvss": p.max_cvss, "cve_count": p.cve_count, "cve_ids": p.cve_ids,
                "remediation": p.remediation,
            }
            for p in rows
        ],
    }


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    if user.role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot delete scans")
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
