"""Local CVE database: search, detail, and offline NVD feed import."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_admin
from ..database import get_db
from ..models import CVE, User
from ..schemas import CVEImportResult, CVEOut
from ..services.cve_import import import_feed_directory

router = APIRouter(prefix="/api/cves", tags=["cves"])


@router.get("", response_model=list[CVEOut])
def search_cves(
    q: str | None = Query(None, description="search id/description/product"),
    severity: str | None = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = db.query(CVE)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            CVE.cve_id.ilike(like),
            CVE.description.ilike(like),
            CVE.cpe_products.ilike(like),
        ))
    if severity:
        query = query.filter(CVE.severity == severity.upper())
    return query.order_by(CVE.cvss_v3_score.desc().nullslast()).offset(offset).limit(limit).all()


@router.get("/count")
def cve_count(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    from sqlalchemy import func
    rows = db.query(CVE.severity, func.count(CVE.id)).group_by(CVE.severity).all()
    by_sev = {sev: cnt for sev, cnt in rows}
    return {"total": db.query(CVE).count(), "by_severity": by_sev}


@router.post("/import", response_model=CVEImportResult)
def import_feeds(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    """Import every NVD JSON feed found in the mounted feed directory."""
    result = import_feed_directory(db)
    return CVEImportResult(**result)


@router.get("/{cve_id}", response_model=CVEOut)
def get_cve(cve_id: str, db: Session = Depends(get_db),
            _: User = Depends(get_current_user)):
    cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve
