"""Run a credentialed (authenticated) Linux/SSH assessment.

Executed in a background THREAD inside the backend process (not via the DB worker)
because the operator-supplied credentials are intentionally never stored in the
database. Credentials live only in this thread's memory for the scan's duration.

Supports multiple hosts in one target (the address may list several IPs/hostnames).
Results (host, vulnerable packages, findings) ARE persisted; credentials are not.
"""
import threading
from datetime import datetime
from typing import Optional

from ..database import SessionLocal
from ..models import ConfigFinding, Finding, Host, Package, Scan, Service
from . import scanlog
from .cve_matcher import correlate_package, latest_fix_version
from .scanner import expand_targets
from .ssh_scanner import collect_host_facts

_SEV_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1, "UNKNOWN": 0}


def _is_backported_pkg(name: str) -> bool:
    """Packages whose distro build backports fixes onto an upstream base version, so
    NVD upstream-range matching over-reports (the kernel being the prime example)."""
    n = (name or "").lower()
    return n == "kernel" or n.startswith(("kernel-", "linux-image", "linux-headers"))


def _assess_host(db, scan, host_addr, port, username, password, key_text, key_passphrase):
    """SSH into one host, enumerate packages, correlate. Returns (pkg_count, vuln_count)."""
    scanlog.log(db, scan, f"[{host_addr}] SSH connecting on port {port}…")
    facts = collect_host_facts(
        host=host_addr, port=port, username=username,
        password=password, key_text=key_text, key_passphrase=key_passphrase,
    )
    scanlog.log(db, scan, f"[{host_addr}] connected — {facts.os_name} {facts.os_version}; "
                          f"{len(facts.packages)} packages; correlating…")
    host = Host(scan_id=scan.id, address=host_addr, hostname="", state="up",
                os_guess=f"{facts.os_name} {facts.os_version}".strip())
    db.add(host)
    db.flush()

    total = len(facts.packages) or 1
    vuln_pkgs = 0
    for idx, (name, clean_ver, full_ver) in enumerate(facts.packages):
        matches = correlate_package(db, name, clean_ver)
        pkg = Package(scan_id=scan.id, host_id=host.id, name=name,
                      version=clean_ver, full_version=full_ver, manager="dpkg")
        if matches:
            vuln_pkgs += 1
            svc = Service(host_id=host.id, port=0, protocol="pkg", state="installed",
                          service_name=name, product=name, version=clean_ver,
                          cpe="", banner=f"installed package {name} {full_ver}")
            db.add(svc)
            db.flush()
            # Aggregate the package's CVEs into ONE consolidated remedy: the single
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
            n = len(set(cve_ids))
            if latest_fix:
                remedy = (f"Upgrade '{name}' from {full_ver} to {latest_fix} or later "
                          f"(single upgrade resolves all {n} matched CVE(s)).")
            else:
                remedy = (f"Upgrade '{name}' (installed {full_ver}) to the latest fixed "
                          f"release from your OS vendor (resolves {n} CVE(s)).")
            # The kernel (and other heavily-backported packages) keeps an upstream base
            # version while the distro backports security fixes into its release build.
            # NVD only knows upstream ranges, so these matches can over-report — flag that.
            if _is_backported_pkg(name):
                remedy += (" NOTE: matched against the upstream kernel version; your "
                           "distro may have already backported these fixes into the "
                           f"'{full_ver}' build — verify against your vendor's security "
                           "errata (RHEL/Debian/Ubuntu) before treating as unpatched.")
            db.add(Finding(scan_id=scan.id, service_id=svc.id, cve_id=top_cve.cve_id,
                           severity=max_sev, cvss_score=max_cvss, match_confidence="high",
                           match_reason=f"[{host_addr}] {name} {clean_ver}: {n} CVE(s); {remedy}"))
            pkg.status = "vulnerable"
            pkg.max_severity = max_sev
            pkg.max_cvss = max_cvss
            pkg.cve_count = n
            pkg.cve_ids = ", ".join(dict.fromkeys(cve_ids))
            pkg.remediation = remedy
        else:
            pkg.status = "ok"
            pkg.max_severity = "NONE"
            pkg.cve_count = 0
            pkg.remediation = ("No known CVE matched this version in the local CVE database. "
                               "Keep current with vendor security updates.")
        db.add(pkg)
        if idx % 200 == 0 and idx:
            scanlog.log(db, scan, f"[{host_addr}] {idx}/{total} packages, {vuln_pkgs} vulnerable so far")
            db.commit()
    db.commit()

    # Persist CIS-style hardening findings (read-only checks run over the same session).
    hardening_fails = 0
    for hr in facts.hardening:
        if hr.status == "fail":
            hardening_fails += 1
        db.add(ConfigFinding(
            scan_id=scan.id, host=host_addr, check_id=hr.check_id, title=hr.title,
            severity=hr.severity, status=hr.status, detail=hr.detail,
            remediation=hr.remediation, evidence=hr.evidence,
        ))
    db.commit()
    if facts.hardening:
        scanlog.log(db, scan, f"[{host_addr}] hardening checks: {hardening_fails} issue(s) "
                              f"across {len(facts.hardening)} checks")
    scanlog.log(db, scan, f"[{host_addr}] done: {len(facts.packages)} packages, {vuln_pkgs} vulnerable")
    return len(facts.packages), vuln_pkgs


def _run(scan_id, address, port, username, password, key_text, key_passphrase):
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

        hosts = expand_targets(address) or [address]
        scanlog.log(db, scan, f"Credentialed Linux assessment of {len(hosts)} host(s): "
                              f"{', '.join(hosts)}")
        tot_pkgs = tot_vuln = 0
        errors = []
        for i, h in enumerate(hosts):
            try:
                p, v = _assess_host(db, scan, h, port, username, password, key_text, key_passphrase)
                tot_pkgs += p
                tot_vuln += v
            except Exception as exc:  # noqa: BLE001 - one host failing shouldn't kill the rest
                db.rollback()
                errors.append(f"{h}: {exc}")
                scanlog.log(db, scan, f"[{h}] FAILED: {exc}")
            scan.progress = min(95, int(95 * (i + 1) / len(hosts)))
            db.commit()

        scan.raw_output = (f"{len(hosts)} host(s); {tot_pkgs} packages; {tot_vuln} vulnerable."
                           + (f" Errors: {'; '.join(errors)}" if errors else ""))
        if errors and len(errors) == len(hosts):
            scan.status = "failed"
            scan.error = "; ".join(errors)[:2000]
        else:
            scan.status = "completed"
        scan.progress = 100
        scan.finished_at = datetime.utcnow()
        db.commit()
        scanlog.log(db, scan, f"Scan {scan.status}: {tot_vuln} vulnerable package(s) "
                              f"across {len(hosts)} host(s).")
        print(f"[credentialed] scan {scan_id} {scan.status}: {tot_pkgs} pkgs, {tot_vuln} vuln", flush=True)
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
