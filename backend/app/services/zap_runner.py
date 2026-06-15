"""Run an authenticated (credentialed) OWASP ZAP web-application scan.

Executed in a background THREAD inside the backend process (not via the DB worker)
because the operator-supplied login credentials are intentionally never stored in
the database — they live only in this thread's memory for the scan's duration.
This mirrors services/credentialed.py (the SSH package audit).

Unauthenticated ZAP scans still run in the DB worker (services/zap_scanner via
worker.py); only scans that carry login credentials are routed here.
"""
import threading
from datetime import datetime
from typing import Optional

from ..database import SessionLocal
from ..models import Scan, WebFinding
from . import scanlog, zap_scanner
from .scanner import expand_targets


def _run(scan_id: int, active: bool, auth: "zap_scanner.ZapAuth"):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        scan.progress = 10
        scan.profile = f"zap-{'active' if active else 'passive'}-authenticated"
        db.commit()

        cb = lambda line: scanlog.log(db, scan, line)
        urls = expand_targets(scan.target.address) or [scan.target.address]
        scanlog.log(db, scan, f"Authenticated OWASP ZAP {'ACTIVE' if active else 'passive'} "
                              f"scan of {len(urls)} URL(s) as user '{auth.username}'.")
        summaries = []
        for ui, url in enumerate(urls):
            scanlog.log(db, scan, f"ZAP {'ACTIVE' if active else 'passive'} scan of {url}")
            result = zap_scanner.run_zap_scan(url, active=active, log_cb=cb, auth=auth)
            summaries.append(result.summary)
            for f in result.findings:
                db.add(WebFinding(
                    scan_id=scan.id, target_url=url,
                    category=f["category"], name=f["name"], severity=f["severity"],
                    cve_id=f.get("cve_id", ""), description=f["description"],
                    evidence=f["evidence"], remediation=f["remediation"],
                    references=f["references"],
                ))
            scan.progress = min(95, int(90 * (ui + 1) / len(urls)))
            db.commit()

        scan.raw_output = "\n".join(summaries)
        scan.status = "completed"
        scan.progress = 100
        scan.finished_at = datetime.utcnow()
        db.commit()
        print(f"[zap-auth] scan {scan_id} completed", flush=True)
    except Exception as exc:  # noqa: BLE001 - background thread must not crash the backend
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.error = str(exc)[:2000]
            scan.finished_at = datetime.utcnow()
            scan.progress = 100
            db.commit()
        print(f"[zap-auth] scan {scan_id} FAILED: {exc}", flush=True)
    finally:
        db.close()


def start_zap_auth_scan(scan_id: int, active: bool, auth: "zap_scanner.ZapAuth"):
    """Launch the authenticated ZAP scan in a daemon thread; credentials stay in memory only."""
    t = threading.Thread(target=_run, args=(scan_id, active, auth), daemon=True)
    t.start()
