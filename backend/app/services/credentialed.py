"""Run a credentialed (authenticated) Linux/SSH assessment.

Executed in a background THREAD inside the backend process (not via the DB worker)
because the operator-supplied credentials are intentionally never stored in the
database. Credentials live only in this thread's memory for the scan's duration.

Results (host, vulnerable packages, findings) ARE persisted; credentials are not.
"""
import threading
from datetime import datetime
from typing import Optional

from ..database import SessionLocal
from ..models import Finding, Host, Package, Scan, Service
from .cve_matcher import correlate_package, latest_fix_version
from .ssh_scanner import collect_host_facts

_SEV_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1, "UNKNOWN": 0}


def _run(scan_id: int, address: str, port: int, username: str,
         password: Optional[str], key_text: Optional[str], key_passphrase: Optional[str]):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        scan.progress = 5
        scan.profile = "credentialed-ssh (linux package audit)"
        db.commit()

        facts = collect_host_facts(
            host=address, port=port, username=username,
            password=password, key_text=key_text, key_passphrase=key_passphrase,
        )
        scan.progress = 30
        scan.raw_output = (
            f"OS: {facts.os_name} ({facts.os_version})\nKernel: {facts.kernel}\n"
            f"Installed packages: {len(facts.packages)}"
        )
        db.commit()

        host = Host(
            scan_id=scan.id, address=address,
            hostname="", state="up",
            os_guess=f"{facts.os_name} {facts.os_version}".strip(),
        )
        db.add(host)
        db.flush()

        manager = "dpkg"  # ssh_scanner records dpkg first, then rpm; label generically
        total = len(facts.packages) or 1
        finding_seen = set()
        vuln_pkgs = 0
        for idx, (name, clean_ver, full_ver) in enumerate(facts.packages):
            matches = correlate_package(db, name, clean_ver)

            # Always record the package in the full inventory.
            pkg = Package(
                scan_id=scan.id, host_id=host.id, name=name,
                version=clean_ver, full_version=full_ver, manager=manager,
            )

            if matches:
                vuln_pkgs += 1
                # persist the package as a 'pkg' service so it flows into findings/reports
                svc = Service(
                    host_id=host.id, port=0, protocol="pkg", state="installed",
                    service_name=name, product=name, version=clean_ver,
                    cpe="", banner=f"installed package {name} {full_ver}",
                )
                db.add(svc)
                db.flush()

                # Aggregate this package's CVEs into ONE consolidated remedy: the single
                # latest version that, once upgraded to, resolves all of them.
                cve_ids, fix_versions = [], []
                top_cve, max_sev, max_cvss = None, "NONE", None
                for cve, confidence, reason, fix_ver in matches:
                    cve_ids.append(cve.cve_id)
                    if fix_ver:
                        fix_versions.append(fix_ver)
                    if _SEV_WEIGHT.get(cve.severity, 0) > _SEV_WEIGHT.get(max_sev, 0):
                        max_sev, top_cve = cve.severity, cve
                    if cve.cvss_v3_score and (max_cvss is None or cve.cvss_v3_score > max_cvss):
                        max_cvss = cve.cvss_v3_score
                top_cve = top_cve or matches[0][0]

                latest_fix = latest_fix_version(fix_versions)
                if latest_fix:
                    remedy = (f"Upgrade '{name}' from {full_ver} to {latest_fix} or later "
                              f"(single upgrade resolves all {len(set(cve_ids))} matched CVE(s)).")
                else:
                    remedy = (f"Upgrade '{name}' (installed {full_ver}) to the latest fixed "
                              f"release from your OS vendor (resolves {len(set(cve_ids))} CVE(s)).")

                # ONE consolidated finding per package (not one per CVE) so the findings
                # list stays manageable; the full CVE list lives on the Package row.
                db.add(Finding(
                    scan_id=scan.id, service_id=svc.id, cve_id=top_cve.cve_id,
                    severity=max_sev, cvss_score=max_cvss,
                    match_confidence="high",
                    match_reason=f"{name} {clean_ver}: {len(set(cve_ids))} CVE(s); {remedy}",
                ))

                pkg.status = "vulnerable"
                pkg.max_severity = max_sev
                pkg.max_cvss = max_cvss
                pkg.cve_count = len(set(cve_ids))
                pkg.cve_ids = ", ".join(dict.fromkeys(cve_ids))
                pkg.remediation = remedy
            else:
                pkg.status = "ok"
                pkg.max_severity = "NONE"
                pkg.cve_count = 0
                pkg.remediation = (
                    "No known CVE matched this version in the local CVE database. "
                    "Keep current with vendor security updates."
                )
            db.add(pkg)

            if idx % 100 == 0:
                scan.progress = min(95, 30 + int(65 * idx / total))
                db.commit()
        db.commit()
        print(f"[credentialed] {len(facts.packages)} packages, {vuln_pkgs} vulnerable", flush=True)

        scan.status = "completed"
        scan.progress = 100
        scan.finished_at = datetime.utcnow()
        db.commit()
        print(f"[credentialed] scan {scan.id} completed "
              f"({len(facts.packages)} pkgs, {len(finding_seen)} findings)", flush=True)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.error = str(exc)[:2000]
            scan.finished_at = datetime.utcnow()
            scan.progress = 100
            db.commit()
        print(f"[credentialed] scan {scan_id} FAILED: {exc}", flush=True)
    finally:
        db.close()


def start_credentialed_scan(scan_id: int, address: str, port: int, username: str,
                            password: Optional[str], key_text: Optional[str],
                            key_passphrase: Optional[str]):
    """Launch the assessment in a daemon thread; credentials stay in memory only."""
    t = threading.Thread(
        target=_run,
        args=(scan_id, address, port, username, password, key_text, key_passphrase),
        daemon=True,
    )
    t.start()
