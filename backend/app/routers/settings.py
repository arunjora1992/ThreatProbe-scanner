"""SMTP settings, configured in the GUI (stored in DB, not .env)."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import get_current_user, require_admin
from ..database import get_db
from ..models import SmtpConfig, User
from ..schemas import SmtpConfigIn, SmtpConfigOut
from ..services import app_settings, mailer

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/app")
def get_app_settings(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Tool-level settings registry + current values, grouped for the Settings GUI."""
    return {"groups": app_settings.all_grouped()}


@router.put("/app")
def update_app_settings(payload: dict, db: Session = Depends(get_db),
                        _: User = Depends(require_admin)):
    """Persist a {key: value} map of setting overrides (validated + clamped)."""
    values = payload.get("values", payload)
    if not isinstance(values, dict):
        raise HTTPException(status_code=400, detail="Expected a {key: value} object")
    app_settings.set_many(db, values)
    return {"groups": app_settings.all_grouped()}


@router.post("/app/reset/{group}")
def reset_app_settings(group: str, db: Session = Depends(get_db),
                       _: User = Depends(require_admin)):
    """Clear overrides for one group, reverting to built-in defaults."""
    if group not in {g for g, _ in app_settings.GROUPS}:
        raise HTTPException(status_code=400, detail="Unknown settings group")
    n = app_settings.reset_group(db, group)
    return {"reset": n, "groups": app_settings.all_grouped()}


def _get_or_create(db: Session) -> SmtpConfig:
    cfg = db.get(SmtpConfig, 1)
    if not cfg:
        cfg = SmtpConfig(id=1)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _to_out(cfg: SmtpConfig) -> SmtpConfigOut:
    return SmtpConfigOut(
        host=cfg.host, port=cfg.port, username=cfg.username, from_addr=cfg.from_addr,
        use_tls=cfg.use_tls, use_ssl=cfg.use_ssl,
        default_recipients=cfg.default_recipients, enabled=cfg.enabled,
        has_password=bool(cfg.password),
    )


@router.get("/smtp", response_model=SmtpConfigOut)
def get_smtp(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return _to_out(_get_or_create(db))


@router.put("/smtp", response_model=SmtpConfigOut)
def update_smtp(payload: SmtpConfigIn, db: Session = Depends(get_db),
                _: User = Depends(require_admin)):
    cfg = _get_or_create(db)
    cfg.host = payload.host.strip()
    cfg.port = payload.port
    cfg.username = payload.username.strip()
    # Only overwrite the password when a new non-empty one is supplied.
    if payload.password:
        cfg.password = payload.password
    cfg.from_addr = payload.from_addr.strip()
    cfg.use_tls = payload.use_tls
    cfg.use_ssl = payload.use_ssl
    cfg.default_recipients = payload.default_recipients.strip()
    cfg.enabled = payload.enabled
    cfg.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(cfg)
    return _to_out(cfg)


@router.post("/smtp/test")
def test_smtp(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    cfg = _get_or_create(db)
    if not cfg.host:
        raise HTTPException(status_code=400, detail="Configure the SMTP host first")
    recipients = [r.strip() for r in (cfg.default_recipients or "").split(",") if r.strip()]
    if not recipients:
        raise HTTPException(status_code=400, detail="Set at least one default recipient to test")
    try:
        mailer.send_email(
            cfg, recipients,
            subject="ThreatProbe Scanner — SMTP test",
            body="This is a test email from ThreatProbe Scanner. SMTP is configured correctly.",
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"SMTP test failed: {exc}")
    return {"sent": True, "recipients": recipients}
