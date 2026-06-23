"""Local CVE database: search, detail, offline NVD feed import, and DB export/upload."""
import os
import shutil
import tempfile
from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from pydantic import BaseModel

from ..auth import get_current_user, require_admin
from ..config import settings
from ..database import get_db
from ..models import CVE, User
from ..schemas import CVEImportResult, CVEOut
from ..services.cve_import import export_cves, import_feed_directory, import_single_file
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
    product: str | None = Query(None, description="filter by affected product/package"),
    cwe: str | None = Query(None, description="filter by CWE id, e.g. CWE-79"),
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
    # Package/product-wise: match only the affected-product index (precise, unlike `q`).
    if product:
        query = query.filter(CVE.cpe_products.ilike(f"%{product}%"))
    # Bug/vulnerability-type-wise: match the CWE id (e.g. CWE-79 = XSS).
    if cwe:
        query = query.filter(CVE.cwe.ilike(f"%{cwe}%"))
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


@router.get("/export")
def export_cve_db(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Download the entire local CVE database as a gzipped JSON file.

    Use this to seed an air-gapped deployment that can't reach NVD: export here, copy the
    file across, and upload it via POST /api/cves/upload (or drop it in the feed dir).
    """
    stamp = datetime.utcnow().strftime("%Y%m%d")
    filename = f"threatprobe-cve-db-{stamp}.json.gz"
    return StreamingResponse(
        export_cves(db),
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/upload", response_model=CVEImportResult)
def upload_cve_db(file: UploadFile = File(...), db: Session = Depends(get_db),
                  _: User = Depends(require_admin)):
    """Import a CVE database export (or any NVD JSON feed) uploaded from another deployment.

    The upload is streamed to disk first so memory stays bounded on large databases, then
    imported with the standard batched upsert (insert new CVEs, update existing ones).
    """
    name = os.path.basename(file.filename or "upload.json")
    if not name.endswith((".json", ".json.gz", ".gz", ".json.xz")):
        raise HTTPException(
            status_code=400,
            detail="Expected a .json, .json.gz or .json.xz file (CVE DB export or NVD feed).",
        )
    # Persist into the mounted feed dir when available (so it can be re-imported later),
    # otherwise a temp dir. Stream the body to avoid loading it all into memory.
    dest_dir = settings.cve_feed_dir if os.path.isdir(settings.cve_feed_dir) else tempfile.gettempdir()
    suffix = ".json.gz" if name.endswith(".gz") else (".json.xz" if name.endswith(".xz") else ".json")
    fd, path = tempfile.mkstemp(prefix="cve-upload-", suffix=suffix, dir=dest_dir)
    try:
        with os.fdopen(fd, "wb") as out:
            shutil.copyfileobj(file.file, out, length=1024 * 1024)
        result = import_single_file(db, path)
        if not result.get("files_processed"):
            raise HTTPException(status_code=400,
                                detail=result.get("message", "No CVE records found in the upload."))
        return CVEImportResult(**result)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


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
