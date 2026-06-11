"""Email reports via the GUI-configured SMTP server (stdlib smtplib)."""
import smtplib
import ssl
from email.message import EmailMessage
from typing import List, Optional, Tuple

from sqlalchemy.orm import Session

from ..models import SmtpConfig


def get_config(db: Session) -> Optional[SmtpConfig]:
    return db.get(SmtpConfig, 1)


def _connect(cfg: SmtpConfig):
    if cfg.use_ssl:
        server = smtplib.SMTP_SSL(cfg.host, cfg.port or 465, timeout=30,
                                  context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(cfg.host, cfg.port or 587, timeout=30)
        if cfg.use_tls:
            server.starttls(context=ssl.create_default_context())
    if cfg.username:
        server.login(cfg.username, cfg.password)
    return server


def send_email(cfg: SmtpConfig, recipients: List[str], subject: str,
               body: str, attachments: List[Tuple[str, bytes, str]] = None) -> None:
    """attachments: list of (filename, content_bytes, mime_subtype)."""
    msg = EmailMessage()
    msg["From"] = cfg.from_addr or cfg.username
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(body)
    for fname, content, subtype in (attachments or []):
        maintype = "application"
        if subtype == "csv":
            maintype, subtype = "text", "csv"
        msg.add_attachment(content, maintype=maintype, subtype=subtype, filename=fname)
    server = _connect(cfg)
    try:
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


def severity_summary(counts: dict) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE", "UNKNOWN"]
    parts = [f"{sev}: {counts[sev]}" for sev in order if counts.get(sev)]
    return "\n".join(parts) if parts else "No findings."
