"""CSV report generation for a scan's findings."""
import csv
import io
from typing import List

from sqlalchemy.orm import Session

from ..models import CVE, Finding, Host, Package, Scan, Service, WebFinding


def build_consolidated_csv(data: dict) -> str:
    """Render a filtered, multi-scan report (from report_query.collect_report_rows) to CSV."""
    out = io.StringIO()
    writer = csv.writer(out)
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


def build_findings_csv(db: Session, scan: Scan) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "Type", "Asset", "Hostname", "Port", "Protocol", "Service/Category",
        "Product", "Version", "Finding/CVE", "Severity", "CVSS",
        "Confidence", "Match/Evidence", "Status", "Description", "Remediation",
        "References", "CWE",
    ])

    # ---- Network / server CVE findings ----
    findings: List[Finding] = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    cve_cache = {}
    for f in findings:
        svc = db.get(Service, f.service_id)
        host = db.get(Host, svc.host_id) if svc else None
        if f.cve_id not in cve_cache:
            cve_cache[f.cve_id] = db.query(CVE).filter(CVE.cve_id == f.cve_id).first()
        cve = cve_cache[f.cve_id]
        writer.writerow([
            "SERVER/CVE",
            host.address if host else "",
            host.hostname if host else "",
            svc.port if svc else "",
            svc.protocol if svc else "",
            svc.service_name if svc else "",
            svc.product if svc else "",
            svc.version if svc else "",
            f.cve_id,
            f.severity,
            f.cvss_score if f.cvss_score is not None else "",
            f.match_confidence,
            f.match_reason,
            f.status,
            (cve.description if cve else "").replace("\n", " "),
            (cve.remediation if cve else "").replace("\n", " "),
            (cve.references if cve else "").replace("\n", "; "),
            cve.cwe if cve else "",
        ])

    # ---- Web / URL penetration test findings ----
    web: List[WebFinding] = db.query(WebFinding).filter(WebFinding.scan_id == scan.id).all()
    for w in web:
        writer.writerow([
            "WEB",
            w.target_url, "", "", "", w.category, "", "",
            w.cve_id or w.name,
            w.severity,
            w.cvss_score if w.cvss_score is not None else "",
            "", (w.evidence or "").replace("\n", " "),
            w.status,
            (w.description or "").replace("\n", " "),
            (w.remediation or "").replace("\n", " "),
            (w.references or "").replace("\n", "; "),
            "",
        ])
    return out.getvalue()
