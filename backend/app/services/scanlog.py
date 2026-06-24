"""Append timestamped lines to a scan's live log (the GUI terminal view)."""
from datetime import datetime


def log(db, scan, line: str):
    from . import app_settings
    ts = datetime.utcnow().strftime("%H:%M:%S")
    scan.log = (scan.log or "") + f"[{ts}] {line}\n"
    # Bound the stored log so a noisy scan can't bloat the row (GUI-configurable cap).
    cap = max(10_000, app_settings.get_int("data_log_max_chars"))
    if len(scan.log) > cap:
        scan.log = scan.log[-cap:]
    db.commit()
