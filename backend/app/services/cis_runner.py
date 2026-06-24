"""Run a CIS-benchmark / hardening audit (scan_type 'cis_benchmark').

Executed in a background THREAD inside the backend (like the credentialed package audit)
because the SSH credentials it uses must never be persisted. Over the SSH session it runs
the official CIS profile via OpenSCAP when the target has it, otherwise a built-in set of
read-only hardening checks. Results are stored as ConfigFinding rows; credentials are not.
"""
import re
import threading
from datetime import datetime
from typing import Optional

from ..database import SessionLocal
from ..models import ConfigFinding, Host, Scan
from . import scanlog
from .cancel import is_cancelled
from .scanner import expand_targets
from .ssh_scanner import collect_compliance

_SEV = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "NONE": 0}


def _level_label(profile: str) -> str:
    """Friendly CIS level from an SSG profile id or our dropdown token.

    Handles e.g. 'xccdf_..._profile_cis_server_l1', '_cis_workstation_l2', and the bare
    '_cis'/'…_profile_cis' which is SSG's Level 2 Server profile (no explicit l2 suffix)."""
    p = (profile or "").lower()
    plat = "Workstation" if "workstation" in p else ("Server" if "server" in p else "")
    if "l2" in p or "level2" in p:
        lvl = "Level 2"
    elif "l1" in p or "level1" in p:
        lvl = "Level 1"
    elif p.endswith("_cis") or p.endswith("profile_cis") or p == "cis":
        lvl, plat = "Level 2", plat or "Server"   # bare CIS profile == Level 2 Server
    else:
        lvl = ""
    label = " ".join(x for x in ("CIS", lvl, plat) if x).strip()
    return label or "CIS"


def _clean_distro(name: str) -> str:
    """Collapse a duplicated trailing version token, e.g. 'CentOS Stream 9 9' -> '…9'."""
    toks = (name or "").split()
    if len(toks) >= 2 and toks[-1] == toks[-2]:
        toks = toks[:-1]
    return " ".join(toks)


def summarize_cis(db, scan) -> dict:
    """Structured CIS run metadata (distro / level / engine / score) for the GUI banner
    and PDF report. Robust to older scans: derives the level from the audit-summary
    detail when present, else from the scan profile, and the distro from the host OS —
    so 'which distro & level' always renders even on scans run before this existed."""
    rows = db.query(ConfigFinding).filter(ConfigFinding.scan_id == scan.id).all()
    summary = next((r for r in rows if r.check_id == "audit-summary"), None)
    detail = (summary.detail if summary else "") or ""
    host = db.query(Host).filter(Host.scan_id == scan.id).first()
    checks = [r for r in rows if r.check_id != "audit-summary"]
    fails = sum(1 for r in checks if r.status == "fail")

    distro = (host.os_guess.strip() if host and host.os_guess else "")
    if not distro and "·" in detail:
        distro = detail.split("·")[0].strip()
    distro = _clean_distro(distro)

    low = detail.lower()
    engine = "OpenSCAP" if "openscap" in low else ("Built-in checks" if "built-in" in low else "")

    m = re.search(r"(CIS Level\s*\d[^·]*)", detail)
    level = m.group(1).strip() if m else ""
    if not level:
        tok = (scan.profile or "").split()[-1] if scan.profile else ""
        if tok and tok != "cis-benchmark":
            level = _level_label(tok)

    ms = re.search(r"score\s*([\d.]+)%", detail)
    score = float(ms.group(1)) if ms else None

    return {
        "distro": distro or "unknown", "level": level or "—",
        "engine": engine or "—", "score": score,
        "total": len(checks), "fails": fails,
    }


def _assess_host(db, scan, host_addr, port, username, password, key_text, key_passphrase,
                 prefer_profile=""):
    scanlog.log(db, scan, f"[{host_addr}] SSH connecting on port {port} for CIS audit…")
    cr = collect_compliance(host=host_addr, port=port, username=username,
                            password=password, key_text=key_text, key_passphrase=key_passphrase,
                            prefer_profile=prefer_profile,
                            log=lambda m: scanlog.log(db, scan, f"[{host_addr}] {m}"))
    host = Host(scan_id=scan.id, address=host_addr, hostname="", state="up",
                os_guess=f"{cr.os_name} {cr.os_version}".strip())
    db.add(host)
    db.flush()

    if cr.mode == "openscap":
        scanlog.log(db, scan, f"[{host_addr}] OpenSCAP profile '{cr.profile}' on "
                              f"{cr.datastream}; {len(cr.results)} rules evaluated"
                              + (f"; compliance score {cr.score:.1f}%" if cr.score is not None else ""))
    else:
        scanlog.log(db, scan, f"[{host_addr}] OpenSCAP not used — ran built-in hardening "
                              f"checks ({len(cr.results)} checks)."
                              + (f" Reason: {cr.reason}" if cr.reason else ""))

    fails = 0
    for r in cr.results:
        if r.status == "fail":
            fails += 1
        db.add(ConfigFinding(
            scan_id=scan.id, host=host_addr, check_id=r.check_id, title=r.title,
            severity=r.severity, status=r.status, detail=r.detail,
            remediation=r.remediation, evidence=r.evidence,
        ))
    # A summary row carries the OS, engine, level + compliance score for the GUI/report.
    osname = (f"{cr.os_name} {cr.os_version}".strip()) or "unknown OS"
    summary = f"{osname} · "
    if cr.mode == "openscap":
        summary += f"OpenSCAP · {_level_label(cr.profile)}"
        if cr.score is not None:
            summary += f" · score {cr.score:.1f}%"
    else:
        summary += "built-in hardening checks"
    summary += f" · {fails} failed of {len(cr.results)} checks"
    db.add(ConfigFinding(
        scan_id=scan.id, host=host_addr, check_id="audit-summary",
        title="CIS audit summary", severity="INFO", status="info",
        detail=summary, remediation="", evidence=cr.datastream or ""))
    db.commit()
    scanlog.log(db, scan, f"[{host_addr}] done: {fails} failed control(s) of {len(cr.results)}.")
    return len(cr.results), fails, cr.score


def _run(scan_id, address, port, username, password, key_text, key_passphrase,
         prefer_profile=""):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        scan.progress = 5
        scan.profile = f"cis-benchmark{(' ' + prefer_profile) if prefer_profile else ''}"
        db.commit()

        hosts = expand_targets(address) or [address]
        scanlog.log(db, scan, f"CIS benchmark audit of {len(hosts)} host(s): {', '.join(hosts)}")
        tot_checks = tot_fails = 0
        errors = []
        cancelled = False
        for i, h in enumerate(hosts):
            if is_cancelled(db, scan_id):
                cancelled = True
                break
            try:
                n, f, _score = _assess_host(db, scan, h, port, username, password,
                                            key_text, key_passphrase, prefer_profile)
                tot_checks += n
                tot_fails += f
            except Exception as exc:  # noqa: BLE001 - one host failing shouldn't kill the rest
                db.rollback()
                errors.append(f"{h}: {exc}")
                scanlog.log(db, scan, f"[{h}] FAILED: {exc}")
            scan.progress = min(95, int(95 * (i + 1) / len(hosts)))
            db.commit()

        scan.raw_output = (f"{len(hosts)} host(s); {tot_fails} failed control(s) of {tot_checks}."
                           + (f" Errors: {'; '.join(errors)}" if errors else ""))
        if cancelled:
            scan.status = "cancelled"
            scan.error = "Scan stopped by operator."
            scanlog.log(db, scan, "Scan stopped by operator.")
        elif errors and len(errors) == len(hosts):
            scan.status = "failed"
            scan.error = "; ".join(errors)[:2000]
        else:
            scan.status = "completed"
        scan.progress = 100
        scan.finished_at = datetime.utcnow()
        db.commit()
        print(f"[cis] scan {scan_id} {scan.status}: {tot_fails}/{tot_checks} failed", flush=True)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.error = str(exc)[:2000]
            scan.finished_at = datetime.utcnow()
            scan.progress = 100
            db.commit()
        print(f"[cis] scan {scan_id} FAILED: {exc}", flush=True)
    finally:
        db.close()


def start_cis_scan(scan_id: int, address: str, port: int, username: str,
                   password: Optional[str], key_text: Optional[str],
                   key_passphrase: Optional[str], prefer_profile: str = ""):
    """Launch the CIS audit in a daemon thread; credentials stay in memory only."""
    t = threading.Thread(
        target=_run,
        args=(scan_id, address, port, username, password, key_text, key_passphrase,
              prefer_profile),
        daemon=True,
    )
    t.start()
