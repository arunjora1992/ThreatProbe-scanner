"""Background scan worker.

A standalone process that polls the database for queued scans and executes them.
Using a DB-backed queue (instead of Redis/Celery) keeps the deployment to the
minimum number of services for air-gapped operation.

Dispatch by scan_type:
  discovery|port|full  -> nmap network/server vulnerability assessment + CVE correlation
  web                  -> URL / web-application penetration test (+ CVE on server banner)
"""
import time
from datetime import datetime

from .database import SessionLocal, engine, Base
from .models import CVE, Finding, Host, Scan, Service, WebFinding
from .config import settings
from .services import scanner, web_scanner, zap_scanner, scanlog
from .services.cve_matcher import correlate_package, correlate_service


def _claim_next_scan(db):
    """Atomically claim the oldest queued scan (SKIP LOCKED for multi-worker safety)."""
    scan = (
        db.query(Scan)
        .filter(Scan.status == "queued")
        # credentialed + CIS scans are executed by the backend (in-memory creds), not here
        .filter(Scan.scan_type.notin_(["credentialed", "cis_benchmark"]))
        .order_by(Scan.created_at.asc())
        .with_for_update(skip_locked=True)
        .first()
    )
    if scan:
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        scan.progress = 5
        db.commit()
    return scan


def _run_network_scan(db, scan: Scan):
    target = scan.target
    cb = lambda line: scanlog.log(db, scan, line)
    targets = scanner.expand_targets(target.address)
    scanlog.log(db, scan, f"Network scan ({scan.scan_type}) of {len(targets)} target(s): "
                          f"{', '.join(targets) or target.address}")
    # For custom scans the operator-supplied flags were stashed in scan.profile.
    custom_flags = scan.profile if scan.scan_type == "custom" else None
    result = scanner.run_scan(target.address, scan.scan_type, custom_flags=custom_flags, log_cb=cb)
    scan.profile = result.flags
    scan.raw_output = result.raw_xml[:1_000_000]
    scan.progress = 40
    db.commit()

    scanlog.log(db, scan, "Correlating discovered services against the CVE database…")
    finding_seen = set()
    for phost in result.hosts:
        host = Host(
            scan_id=scan.id, address=phost.address, hostname=phost.hostname,
            state=phost.state, os_guess=phost.os_guess,
        )
        db.add(host)
        db.flush()
        scanlog.log(db, scan, f"Host {phost.address} up — {len(phost.services)} open service(s)")
        for psvc in phost.services:
            svc = Service(
                host_id=host.id, port=psvc.port, protocol=psvc.protocol,
                state=psvc.state, service_name=psvc.service_name,
                product=psvc.product, version=psvc.version, cpe=psvc.cpe,
                banner=psvc.banner,
            )
            db.add(svc)
            db.flush()
            # correlate this service against the local CVE DB
            for cve, confidence, reason, _fix in correlate_service(db, svc):
                key = (svc.id, cve.cve_id)
                if key in finding_seen:
                    continue
                finding_seen.add(key)
                db.add(Finding(
                    scan_id=scan.id, service_id=svc.id, cve_id=cve.cve_id,
                    severity=cve.severity, cvss_score=cve.cvss_v3_score,
                    match_confidence=confidence, match_reason=reason,
                ))
        db.commit()
    scanlog.log(db, scan, f"Correlation complete: {len(finding_seen)} finding(s).")
    scan.progress = 95
    db.commit()


def _run_web_scan(db, scan: Scan):
    target = scan.target
    scan.profile = "web-assessment"
    urls = scanner.expand_targets(target.address) or [target.address]
    summaries = []
    for ui, url in enumerate(urls):
        scanlog.log(db, scan, f"Built-in web checks against {url}…")
        result = web_scanner.run_web_scan(url)
        summaries.append(result.summary)
        for f in result.findings:
            db.add(WebFinding(
                scan_id=scan.id, target_url=url,
                category=f["category"], name=f["name"], severity=f["severity"],
                description=f["description"], evidence=f["evidence"],
                remediation=f["remediation"], references=f["references"], cve_id=f["cve_id"],
            ))
        # Correlate detected server software (precise, version-aware).
        for software in result.detected_software:
            product, version = _split_software(software)
            if not product or not version:
                continue
            for cve, confidence, reason, _fix in correlate_package(db, product, version):
                db.add(WebFinding(
                    scan_id=scan.id, target_url=url,
                    category="Software", name=f"{cve.cve_id} affects {software}",
                    severity=cve.severity, cvss_score=cve.cvss_v3_score, cve_id=cve.cve_id,
                    description=cve.description,
                    remediation=f"{reason}. {cve.remediation}",
                    references=cve.references,
                    evidence=f"Server software banner: {software} ({reason})",
                ))
        scanlog.log(db, scan, f"{url}: {len(result.findings)} finding(s).")
        scan.progress = min(95, int(95 * (ui + 1) / len(urls)))
        db.commit()
    scan.raw_output = "\n".join(summaries)
    db.commit()


def _split_software(banner: str):
    """Split a 'Server: Apache/2.4.49 (Unix)' style banner into (product, version)."""
    token = banner.split()[0] if banner else ""
    if "/" in token:
        prod, _, ver = token.partition("/")
        return prod.strip().lower(), ver.strip()
    return token.strip().lower(), ""


def _run_zap_scan(db, scan: Scan, active: bool):
    target = scan.target
    scan.profile = f"zap-{'active' if active else 'passive'}"
    scan.progress = 10
    db.commit()
    cb = lambda line: scanlog.log(db, scan, line)
    urls = scanner.expand_targets(target.address) or [target.address]
    summaries = []
    for ui, url in enumerate(urls):
        scanlog.log(db, scan, f"OWASP ZAP {'ACTIVE' if active else 'passive'} scan of {url}")
        result = zap_scanner.run_zap_scan(url, active=active, log_cb=cb)
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
    db.commit()


def process_scan(db, scan: Scan):
    try:
        if scan.scan_type == "web":
            _run_web_scan(db, scan)
        elif scan.scan_type in ("zap_passive", "zap_active"):
            _run_zap_scan(db, scan, active=(scan.scan_type == "zap_active"))
        else:
            _run_network_scan(db, scan)
        scan.status = "completed"
        scan.progress = 100
        scan.finished_at = datetime.utcnow()
        db.commit()
        print(f"[worker] scan {scan.id} completed", flush=True)
    except Exception as exc:  # noqa: BLE001 - worker must never die on one bad scan
        db.rollback()
        scan.status = "failed"
        scan.error = str(exc)[:2000]
        scan.finished_at = datetime.utcnow()
        scan.progress = 100
        db.commit()
        print(f"[worker] scan {scan.id} FAILED: {exc}", flush=True)


def main():
    # Ensure tables exist (the API also does this; harmless if already created).
    Base.metadata.create_all(bind=engine)
    print(f"[worker] started; polling every {settings.worker_poll_interval}s; "
          f"nmap={'available' if scanner.nmap_available() else 'MISSING'}", flush=True)
    while True:
        db = SessionLocal()
        try:
            scan = _claim_next_scan(db)
            if scan:
                print(f"[worker] picked up scan {scan.id} ({scan.scan_type})", flush=True)
                process_scan(db, scan)
            else:
                time.sleep(settings.worker_poll_interval)
        except Exception as exc:  # noqa: BLE001
            print(f"[worker] loop error: {exc}", flush=True)
            db.rollback()
            time.sleep(settings.worker_poll_interval)
        finally:
            db.close()


if __name__ == "__main__":
    main()
