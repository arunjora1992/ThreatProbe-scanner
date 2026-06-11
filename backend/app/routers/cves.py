"""Local CVE database: search, detail, and offline NVD feed import."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from pydantic import BaseModel

from ..auth import get_current_user, require_admin
from ..database import get_db
from ..models import CVE, User
from ..schemas import CVEImportResult, CVEOut
from ..services.cve_import import import_feed_directory
from ..services import cve_updater


class UpdateConfigIn(BaseModel):
    enabled: bool = False
    interval_hours: int = 24
    source: str = "online"  # online | feed_dir

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


def _update_config_out(cfg):
    return {
        "enabled": cfg.enabled, "interval_hours": cfg.interval_hours, "source": cfg.source,
        "last_run": cfg.last_run.isoformat() if cfg.last_run else None,
        "last_status": cfg.last_status, "last_message": cfg.last_message,
        "last_added": cfg.last_added,
    }


@router.get("/update/config")
def get_update_config(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return _update_config_out(cve_updater.get_config(db))


@router.put("/update/config")
def set_update_config(payload: UpdateConfigIn, db: Session = Depends(get_db),
                      _: User = Depends(require_admin)):
    if payload.source not in ("online", "feed_dir"):
        raise HTTPException(status_code=400, detail="source must be 'online' or 'feed_dir'")
    if payload.interval_hours < 1:
        raise HTTPException(status_code=400, detail="interval_hours must be >= 1")
    cfg = cve_updater.get_config(db)
    cfg.enabled = payload.enabled
    cfg.interval_hours = payload.interval_hours
    cfg.source = payload.source
    db.commit()
    return _update_config_out(cfg)


@router.post("/update/run")
def run_update_now(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    """Trigger a CVE update immediately (online download or feed-dir re-import)."""
    res = cve_updater.run_update(db)
    return {"message": res.get("message", ""), "imported": res.get("imported", 0)}


@router.get("/{cve_id}", response_model=CVEOut)
def get_cve(cve_id: str, db: Session = Depends(get_db),
            _: User = Depends(get_current_user)):
    cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve
