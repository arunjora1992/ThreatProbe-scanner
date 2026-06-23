"""Run an enhanced OWASP ZAP web-application scan in the backend.

Executed in a background THREAD inside the backend process (not via the DB worker)
when the scan needs either:
  - authentication — the operator-supplied login credentials are intentionally never
    stored in the database; they live only in this thread's memory for the scan's
    duration (mirrors services/credentialed.py, the SSH package audit), or
  - the AJAX (browser-driven) spider for JavaScript/SPA crawling.

Plain unauthenticated, non-AJAX ZAP scans still run in the DB worker
(services/zap_scanner via worker.py).
"""
import threading
from datetime import datetime
from typing import Optional

from ..database import SessionLocal
from ..models import Scan, WebFinding
from . import scanlog, zap_scanner
from .cancel import is_cancelled
from .scanner import expand_targets


def _run(scan_id: int, active: bool, auth: "Optional[zap_scanner.ZapAuth]", ajax: bool):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        scan.progress = 10
        tags = "".join(t for t in (("-auth" if auth else ""), ("-ajax" if ajax else "")))
        scan.profile = f"zap-{'active' if active else 'passive'}{tags}"
        db.commit()

        cb = lambda line: scanlog.log(db, scan, line)
        urls = expand_targets(scan.target.address) or [scan.target.address]
        who = f" as user '{auth.username}'" if auth else ""
        scanlog.log(db, scan, f"OWASP ZAP {'ACTIVE' if active else 'passive'} scan of "
                              f"{len(urls)} URL(s){who}"
                              f"{' with AJAX (browser) spider' if ajax else ''}.")
        summaries = []
        cancelled = False
        for ui, url in enumerate(urls):
            if is_cancelled(db, scan_id):
                cancelled = True
                break
            scanlog.log(db, scan, f"ZAP {'ACTIVE' if active else 'passive'} scan of {url}")
            result = zap_scanner.run_zap_scan(url, active=active, log_cb=cb,
                                              auth=auth, ajax_spider=ajax)
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
        scan.status = "cancelled" if cancelled else "completed"
        if cancelled:
            scan.error = "Scan stopped by operator."
            scanlog.log(db, scan, "Scan stopped by operator.")
        scan.progress = 100
        scan.finished_at = datetime.utcnow()
        db.commit()
        print(f"[zap-bg] scan {scan_id} {scan.status}", flush=True)
    except Exception as exc:  # noqa: BLE001 - background thread must not crash the backend
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.error = str(exc)[:2000]
            scan.finished_at = datetime.utcnow()
            scan.progress = 100
            db.commit()
        print(f"[zap-bg] scan {scan_id} FAILED: {exc}", flush=True)
    finally:
        db.close()


def start_zap_bg_scan(scan_id: int, active: bool,
                      auth: "Optional[zap_scanner.ZapAuth]" = None, ajax: bool = False):
    """Launch an authenticated and/or AJAX ZAP scan in a daemon thread.

    Any login credentials stay in memory only and are never persisted.
    """
    t = threading.Thread(target=_run, args=(scan_id, active, auth, ajax), daemon=True)
    t.start()
