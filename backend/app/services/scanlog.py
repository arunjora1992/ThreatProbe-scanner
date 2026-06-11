"""Append timestamped lines to a scan's live log (the GUI terminal view)."""
from datetime import datetime


def log(db, scan, line: str):
    ts = datetime.utcnow().strftime("%H:%M:%S")
    scan.log = (scan.log or "") + f"[{ts}] {line}\n"
    # Bound the stored log so a noisy scan can't bloat the row.
    if len(scan.log) > 200_000:
        scan.log = scan.log[-200_000:]
    db.commit()
