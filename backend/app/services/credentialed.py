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
from ..models import CVE, Finding, Host, Package, Scan, Service
from . import distro_feeds, scanlog
from .cve_matcher import correlate_package, latest_fix_version
from .scanner import expand_targets
from .ssh_scanner import collect_host_facts

_SEV_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1, "UNKNOWN": 0}


def _is_backported_pkg(name: str) -> bool:
    """Packages whose distro build backports fixes onto an upstream base version, so
    NVD upstream-range matching over-reports (the kernel being the prime example)."""
    n = (name or "").lower()
    return n == "kernel" or n.startswith(("kernel-", "linux-image", "linux-headers"))


# Vendor advisory severity words -> our scale (used when a distro CVE isn't in the NVD DB).
_VENDOR_SEV = {
    "critical": "CRITICAL", "important": "HIGH", "high": "HIGH",
    "moderate": "MEDIUM", "medium": "MEDIUM", "low": "LOW", "negligible": "LOW",
}


def _distro_norm_matches(db, distro, release, manager, name, full_ver):
    """Backport-aware matches from distro advisories, enriched with NVD severity/CVSS."""
    dmatches = distro_feeds.correlate_distro(db, distro, release, manager, name, full_ver)
    if not dmatches:
        return []
    cve_rows = {c.cve_id: c for c in db.query(CVE).filter(
        CVE.cve_id.in_([m["cve_id"] for m in dmatches])).all()}
    out = []
    for m in dmatches:
        c = cve_rows.get(m["cve_id"])
        sev = (c.severity if c and c.severity not in ("", "UNKNOWN")
               else _VENDOR_SEV.get((m.get("severity") or "").lower(), "UNKNOWN"))
        out.append({"cve_id": m["cve_id"], "severity": sev,
                    "cvss": c.cvss_v3_score if c else None,
                    "fixed_version": m.get("fixed_version", ""),
                    "advisory_id": m.get("advisory_id", "")})
    return out


def _nvd_norm_matches(db, name, clean_ver):
    """Upstream NVD version-range matches, normalised to the common shape."""
    out = []
    for cve, _conf, _reason, fix_ver in correlate_package(db, name, clean_ver):
        out.append({"cve_id": cve.cve_id, "severity": cve.severity,
                    "cvss": cve.cvss_v3_score, "fixed_version": fix_ver, "advisory_id": ""})
    return out


def _assess_host(db, scan, host_addr, port, username, password, key_text, key_passphrase):
    """SSH into one host, enumerate packages, correlate. Returns (pkg_count, vuln_count)."""
    scanlog.log(db, scan, f"[{host_addr}] SSH connecting on port {port}…")
    facts = collect_host_facts(
        host=host_addr, port=port, username=username,
        password=password, key_text=key_text, key_passphrase=key_passphrase,
    )
    distro, manager = distro_feeds.distro_key(facts.os_id)
    use_distro = bool(distro) and distro_feeds.has_advisories(db, distro)
    scanlog.log(db, scan, f"[{host_addr}] connected — {facts.os_name} {facts.os_version}; "
                          f"{len(facts.packages)} packages; correlating "
                          + (f"against {distro} security advisories (backport-aware)…"
                             if use_distro else "against NVD (no distro feed loaded)…"))
    host = Host(scan_id=scan.id, address=host_addr, hostname="", state="up",
                os_guess=f"{facts.os_name} {facts.os_version}".strip())
    db.add(host)
    db.flush()

    total = len(facts.packages) or 1
    vuln_pkgs = 0
    for idx, (name, clean_ver, full_ver) in enumerate(facts.packages):
        if use_distro:
            matches = _distro_norm_matches(db, distro, facts.os_version, manager, name, full_ver)
        else:
            matches = _nvd_norm_matches(db, name, clean_ver)
        pkg = Package(scan_id=scan.id, host_id=host.id, name=name,
                      version=clean_ver, full_version=full_ver, manager=manager)
        if matches:
            vuln_pkgs += 1
            svc = Service(host_id=host.id, port=0, protocol="pkg", state="installed",
                          service_name=name, product=name, version=clean_ver,
                          cpe="", banner=f"installed package {name} {full_ver}")
            db.add(svc)
            db.flush()
            # Aggregate the package's CVEs into ONE consolidated remedy.
            cve_ids, fix_versions = [], []
            top_cve_id, max_sev, max_cvss, top_adv = None, "NONE", None, ""
            for m in matches:
                cve_ids.append(m["cve_id"])
                if m.get("fixed_version"):
                    fix_versions.append(m["fixed_version"])
                if _SEV_WEIGHT.get(m["severity"], 0) > _SEV_WEIGHT.get(max_sev, 0):
                    max_sev, top_cve_id, top_adv = m["severity"], m["cve_id"], m.get("advisory_id", "")
                if m.get("cvss") and (max_cvss is None or m["cvss"] > max_cvss):
                    max_cvss = m["cvss"]
            top_cve_id = top_cve_id or matches[0]["cve_id"]
            latest_fix = latest_fix_version(fix_versions)
            n = len(set(cve_ids))
            if use_distro:
                # Distro-accurate: the advisory's fixed version already accounts for backports.
                if latest_fix:
                    remedy = (f"Upgrade '{name}' from {full_ver} to {latest_fix} or later per "
                              f"your distro's security advisory ({top_adv or 'vendor errata'}); "
                              f"resolves {n} CVE(s).")
                else:
                    remedy = (f"'{name}' {full_ver} is affected by {n} CVE(s) with no fixed "
                              f"release yet from your distro — monitor vendor errata.")
            else:
                if latest_fix:
                    remedy = (f"Upgrade '{name}' from {full_ver} to {latest_fix} or later "
                              f"(single upgrade resolves all {n} matched CVE(s)).")
                else:
                    remedy = (f"Upgrade '{name}' (installed {full_ver}) to the latest fixed "
                              f"release from your OS vendor (resolves {n} CVE(s)).")
                # Upstream NVD matching over-reports backported packages — flag the kernel etc.
                if _is_backported_pkg(name):
                    remedy += (" NOTE: matched against the upstream version; your distro may "
                               f"have backported these fixes into '{full_ver}' — load a distro "
                               "security feed (CVE Database → Import distro feeds) for accurate "
                               "results, or verify against vendor errata.")
            db.add(Finding(scan_id=scan.id, service_id=svc.id, cve_id=top_cve_id,
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
            pkg.remediation = ("No known CVE matched this version in the "
                               + ("distro security feed." if use_distro
                                  else "local CVE database.")
                               + " Keep current with vendor security updates.")
        db.add(pkg)
        if idx % 200 == 0 and idx:
            scanlog.log(db, scan, f"[{host_addr}] {idx}/{total} packages, {vuln_pkgs} vulnerable so far")
            db.commit()
    db.commit()
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
