"""CSV report generation for a scan's findings."""
import csv
import io
from datetime import datetime
from typing import List

from sqlalchemy.orm import Session

from ..models import (BrandingConfig, CVE, ConfigFinding, Finding, Host, Package, Scan,
                      Service, WebFinding)


def _brand_name(db=None) -> str:
    try:
        if db is None:
            from ..database import SessionLocal
            s = SessionLocal()
            try:
                b = s.query(BrandingConfig).first()
                return b.app_name if b and b.app_name else "ThreatProbe Scanner"
            finally:
                s.close()
        b = db.query(BrandingConfig).first()
        return b.app_name if b and b.app_name else "ThreatProbe Scanner"
    except Exception:
        return "ThreatProbe Scanner"


def _brand_header(w, db, title: str):
    """Two-line provenance header on every CSV: tool name + generated timestamp."""
    w.writerow([f"{_brand_name(db)} — {title}"])
    w.writerow([f"Generated {datetime.utcnow():%Y-%m-%d %H:%M} UTC"])
    w.writerow([])


def build_consolidated_csv(data: dict) -> str:
    """Render a filtered, multi-scan report (from report_query.collect_report_rows) to CSV."""
    out = io.StringIO()
    writer = csv.writer(out)
    _brand_header(writer, None, "Consolidated vulnerability report")
    writer.writerow([
        "Type", "Scan", "Target", "Asset", "Port", "Service/Category", "Product",
        "Version", "Finding/CVE", "Severity", "CVSS", "Confidence",
        "Match/Evidence", "Status", "Description", "Remediation", "References", "CWE",
    ])
    for r in data.get("cve", []):
        writer.writerow([
            "SERVER/CVE", r["scan_id"], r["target"], r["host"], r["port"],
            r["service"], r["product"], r["version"], r["cve_id"], r["severity"],
            r["cvss"] if r["cvss"] is not None else "", r["confidence"], r["match_reason"],
            r["status"], (r["description"] or "").replace("\n", " "),
            (r["remediation"] or "").replace("\n", " "),
            (r["references"] or "").replace("\n", "; "), r["cwe"],
        ])
    for r in data.get("web", []):
        writer.writerow([
            "WEB", r["scan_id"], r["target"], r["target_url"], "", r["category"], "", "",
            r["cve_id"] or r["name"], r["severity"],
            r["cvss"] if r["cvss"] is not None else "", "",
            (r["evidence"] or "").replace("\n", " "), r["status"],
            (r["description"] or "").replace("\n", " "),
            (r["remediation"] or "").replace("\n", " "),
            (r["references"] or "").replace("\n", "; "), "",
        ])
    for r in data.get("package", []):
        writer.writerow([
            "PACKAGE", r["scan_id"], r["target"], "", "", "package", r["name"],
            r["full_version"] or r["version"], r["cve_ids"] or "", r["severity"],
            r["cvss"] if r["cvss"] is not None else "", "", r["status"], r["status"],
            f"{r['cve_count']} CVE(s)", (r["remediation"] or "").replace("\n", " "), "", "",
        ])
    return out.getvalue()


def build_packages_csv(db: Session, scan: Scan) -> str:
    """Full installed-package inventory: version, criticality, CVEs, patching remedy."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "Package", "Installed Version", "Full Version", "Manager", "Status",
        "Max Severity", "Max CVSS", "CVE Count", "CVEs", "Patching Remedy",
    ])
    sev = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1}
    rows: List[Package] = db.query(Package).filter(Package.scan_id == scan.id).all()
    rows.sort(key=lambda p: (sev.get(p.max_severity, 0), p.max_cvss or 0, p.name), reverse=True)
    for p in rows:
        writer.writerow([
            p.name, p.version, p.full_version, p.manager, p.status,
            p.max_severity, p.max_cvss if p.max_cvss is not None else "",
            p.cve_count, p.cve_ids, (p.remediation or "").replace("\n", " "),
        ])
    return out.getvalue()


_SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "NONE": 0}
_nl = lambda s: (s or "").replace("\n", " ")


def build_findings_csv(db: Session, scan: Scan) -> str:
    """A CSV whose columns suit the scan type (no irrelevant blank columns)."""
    out = io.StringIO()
    w = csv.writer(out)
    _brand_header(w, db, f"{scan.scan_type} report · scan #{scan.id}")
    t = scan.scan_type

    if t == "cis_benchmark":
        w.writerow(["Result", "Severity", "Host", "Control ID", "Control", "Detail",
                    "Remediation", "Evidence"])
        cfg = [c for c in db.query(ConfigFinding).filter(ConfigFinding.scan_id == scan.id).all()
               if c.check_id != "audit-summary"]
        cfg.sort(key=lambda c: (c.status == "fail", _SEV_RANK.get(c.severity, 0)), reverse=True)
        for c in cfg:
            w.writerow([c.status, (c.severity if c.status == "fail" else ""), c.host,
                        c.check_id, c.title, _nl(c.detail),
                        _nl(c.remediation) if c.status == "fail" else "", _nl(c.evidence)])
        return out.getvalue()

    if t in ("web", "zap_passive", "zap_active"):
        w.writerow(["URL", "Category", "Finding", "Severity", "CVSS", "CVE", "Status",
                    "Description", "Evidence", "Remediation", "References"])
        web = db.query(WebFinding).filter(WebFinding.scan_id == scan.id).all()
        web.sort(key=lambda x: (_SEV_RANK.get(x.severity, 0), x.cvss_score or 0), reverse=True)
        for x in web:
            w.writerow([x.target_url, x.category, x.name, x.severity,
                        x.cvss_score if x.cvss_score is not None else "", x.cve_id, x.status,
                        _nl(x.description), _nl(x.evidence), _nl(x.remediation),
                        (x.references or "").replace("\n", "; ")])
        return out.getvalue()

    if t == "credentialed":
        # Package/CVE audit — package-centric columns.
        w.writerow(["Package", "Installed Version", "Status", "Max Severity", "Max CVSS",
                    "CVE Count", "CVEs", "Patching Remediation"])
        rows = db.query(Package).filter(Package.scan_id == scan.id).all()
        rows.sort(key=lambda p: (_SEV_RANK.get(p.max_severity, 0), p.max_cvss or 0), reverse=True)
        for p in rows:
            w.writerow([p.name, p.full_version or p.version, p.status, p.max_severity,
                        p.max_cvss if p.max_cvss is not None else "", p.cve_count,
                        p.cve_ids, _nl(p.remediation)])
        return out.getvalue()

    # Network scans (discovery/port/full/custom): host/port + CVE findings.
    w.writerow(["Host", "Hostname", "Port", "Protocol", "Service", "Product", "Version",
                "CVE", "Severity", "CVSS", "Match / fix", "Status", "Description",
                "Remediation", "References", "CWE"])
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    findings.sort(key=lambda f: (_SEV_RANK.get(f.severity, 0), f.cvss_score or 0), reverse=True)
    cve_cache = {}
    for f in findings:
        svc = db.get(Service, f.service_id)
        host = db.get(Host, svc.host_id) if svc else None
        if f.cve_id not in cve_cache:
            cve_cache[f.cve_id] = db.query(CVE).filter(CVE.cve_id == f.cve_id).first()
        cve = cve_cache[f.cve_id]
        w.writerow([
            host.address if host else "", host.hostname if host else "",
            svc.port if svc else "", svc.protocol if svc else "",
            svc.service_name if svc else "", svc.product if svc else "",
            svc.version if svc else "", f.cve_id, f.severity,
            f.cvss_score if f.cvss_score is not None else "", _nl(f.match_reason), f.status,
            _nl(cve.description if cve else ""), _nl(cve.remediation if cve else ""),
            (cve.references if cve else "").replace("\n", "; "), cve.cwe if cve else "",
        ])
    return out.getvalue()
