"""White-label branding: app name + logo, customizable from the GUI.

GET is public (the login page needs it before auth). PUT is admin-only.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import require_admin
from ..database import get_db
from ..models import BrandingConfig, User

router = APIRouter(prefix="/api/branding", tags=["branding"])

_MAX_LOGO_BYTES = 512 * 1024  # cap the stored data: URI so the table stays small


class BrandingIn(BaseModel):
    app_name: str = "ThreatProbe Scanner"
    logo_emoji: str = "🛡️"
    logo_data_url: str | None = None      # None = leave unchanged; "" = clear
    favicon_data_url: str | None = None   # None = leave unchanged; "" = clear


def _get(db: Session) -> BrandingConfig:
    cfg = db.get(BrandingConfig, 1)
    if not cfg:
        cfg = BrandingConfig(id=1)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _out(cfg: BrandingConfig) -> dict:
    return {"app_name": cfg.app_name or "ThreatProbe Scanner",
            "logo_emoji": cfg.logo_emoji or "🛡️",
            "logo_data_url": cfg.logo_data_url or "",
            "favicon_data_url": cfg.favicon_data_url or ""}


def _validate_data_uri(url: str, field: str):
    if url and not url.startswith("data:image/"):
        raise HTTPException(status_code=400, detail=f"{field} must be a data:image/* URI.")
    if len(url) > _MAX_LOGO_BYTES:
        raise HTTPException(status_code=400, detail=f"{field} too large (max ~512 KB).")


@router.get("")
def get_branding(db: Session = Depends(get_db)):
    """Public — the login screen renders branding before authentication."""
    return _out(_get(db))


@router.put("")
def set_branding(payload: BrandingIn, db: Session = Depends(get_db),
                 _: User = Depends(require_admin)):
    cfg = _get(db)
    cfg.app_name = (payload.app_name or "ThreatProbe Scanner").strip()[:100]
    cfg.logo_emoji = (payload.logo_emoji or "🛡️").strip()[:16]
    if payload.logo_data_url is not None:
        url = payload.logo_data_url.strip()
        _validate_data_uri(url, "logo")
        cfg.logo_data_url = url
    if payload.favicon_data_url is not None:
        fav = payload.favicon_data_url.strip()
        _validate_data_uri(fav, "favicon")
        cfg.favicon_data_url = fav
    db.commit()
    return _out(cfg)
