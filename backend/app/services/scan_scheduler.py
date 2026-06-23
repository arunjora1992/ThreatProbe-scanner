"""Recurring-scan scheduler.

A background thread (started by the API) checks ScanSchedule rows and, when one is due,
enqueues a Scan (status 'queued') that the DB worker then runs. Only credential-less scan
types are schedulable; authenticated/SSH scans need in-memory credentials we never store.
"""
import threading
import time
from datetime import datetime, timedelta

from ..database import SessionLocal
from ..models import Scan, ScanSchedule

SCHEDULABLE_TYPES = {"discovery", "port", "full", "custom", "web", "zap_passive", "zap_active"}
_CHECK_INTERVAL = 60  # seconds


def due_schedules(db):
    now = datetime.utcnow()
    return (db.query(ScanSchedule)
            .filter(ScanSchedule.enabled.is_(True))
            .filter((ScanSchedule.next_run.is_(None)) | (ScanSchedule.next_run <= now))
            .all())


def enqueue(db, sch: ScanSchedule) -> Scan:
    """Create a queued Scan for a schedule and advance its run timestamps."""
    scan = Scan(
        target_id=sch.target_id,
        scan_type=sch.scan_type,
        profile=(sch.custom_flags or "") if sch.scan_type == "custom" else "",
        status="queued",
        created_by=f"schedule#{sch.id}",
    )
    db.add(scan)
    now = datetime.utcnow()
    sch.last_run = now
    sch.next_run = now + timedelta(hours=max(1, sch.interval_hours or 24))
    db.commit()
    db.refresh(scan)
    return scan


def run_due(db) -> int:
    n = 0
    for sch in due_schedules(db):
        if sch.scan_type not in SCHEDULABLE_TYPES:
            continue
        try:
            scan = enqueue(db, sch)
            print(f"[scheduler] schedule {sch.id} -> queued scan {scan.id} "
                  f"({sch.scan_type} on target {sch.target_id})", flush=True)
            n += 1
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            print(f"[scheduler] schedule {sch.id} failed to enqueue: {exc}", flush=True)
    return n


def _loop():
    while True:
        try:
            db = SessionLocal()
            run_due(db)
            db.close()
        except Exception as exc:  # noqa: BLE001
            print(f"[scheduler] loop error: {exc}", flush=True)
        time.sleep(_CHECK_INTERVAL)


def start_scheduler():
    threading.Thread(target=_loop, daemon=True).start()
    print("[scheduler] scan scheduler started", flush=True)
