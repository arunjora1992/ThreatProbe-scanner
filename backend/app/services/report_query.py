"""Filter/aggregation layer for consolidated, filtered reports.

`collect_report_rows` gathers findings ACROSS scans (optionally scoped to a target),
applying any combination of filters, and returns plain dict rows so the CSV/PDF
builders don't each re-query the database.
"""
from typing import Iterable, Optional

from sqlalchemy.orm import Session

from ..models import CVE, Finding, Host, Package, Scan, Service, Target, WebFinding

ALL_TYPES = ("cve", "web", "package")


def _norm_set(values: Optional[Iterable[str]], upper=False):
    if not values:
        return None
    out = {(_v.strip().upper() if upper else _v.strip()) for _v in values if _v and _v.strip()}
    return out or None


def collect_report_rows(
    db: Session,
    *,
    target_id: Optional[int] = None,
    scan_ids: Optional[Iterable[int]] = None,
    severities: Optional[Iterable[str]] = None,
    statuses: Optional[Iterable[str]] = None,
    types: Optional[Iterable[str]] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    cve_id: Optional[str] = None,
    package: Optional[str] = None,
    confidences: Optional[Iterable[str]] = None,
    vulnerable_only: bool = False,
) -> dict:
    severities = _norm_set(severities, upper=True)
    statuses = _norm_set(statuses)
    confidences = _norm_set(confidences)
    types = _norm_set([t.lower() for t in types]) if types else None
    want = {t for t in (types or ALL_TYPES)}

    # Target name lookup for context columns.
    targets = {t.id: t for t in db.query(Target).all()}
    scan_target = {s.id: s.target_id for s in db.query(Scan.id, Scan.target_id).all()}

    def target_label(tid):
        t = targets.get(tid)
        return f"{t.name} ({t.address})" if t else str(tid)

    cve_rows, web_rows, pkg_rows = [], [], []

    # ---- CVE / network-server findings ----
    if "cve" in want:
        q = (
            db.query(Finding, Service, Host, Scan)
            .join(Service, Finding.service_id == Service.id)
            .join(Host, Service.host_id == Host.id)
            .join(Scan, Finding.scan_id == Scan.id)
        )
        if target_id is not None:
            q = q.filter(Scan.target_id == target_id)
        if scan_ids:
            q = q.filter(Finding.scan_id.in_(list(scan_ids)))
        if severities:
            q = q.filter(Finding.severity.in_(severities))
        if statuses:
            q = q.filter(Finding.status.in_(statuses))
        if confidences:
            q = q.filter(Finding.match_confidence.in_(confidences))
        if host:
            q = q.filter(Host.address.ilike(f"%{host}%"))
        if port:
            q = q.filter(Service.port == port)
        if cve_id:
            q = q.filter(Finding.cve_id.ilike(f"%{cve_id}%"))

        rows = q.all()
        cve_cache = {}
        for f, svc, h, sc in rows:
            if f.cve_id not in cve_cache:
                cve_cache[f.cve_id] = db.query(CVE).filter(CVE.cve_id == f.cve_id).first()
            cve = cve_cache[f.cve_id]
            cve_rows.append({
                "scan_id": sc.id, "target": target_label(sc.target_id),
                "host": h.address, "hostname": h.hostname,
                "port": svc.port, "protocol": svc.protocol,
                "service": svc.service_name, "product": svc.product, "version": svc.version,
                "cve_id": f.cve_id, "severity": f.severity, "cvss": f.cvss_score,
                "confidence": f.match_confidence, "match_reason": f.match_reason,
                "status": f.status,
                "description": cve.description if cve else "",
                "remediation": cve.remediation if cve else "",
                "references": cve.references if cve else "",
                "cwe": cve.cwe if cve else "",
            })

    # ---- Web / URL findings ----
    if "web" in want and not vulnerable_only:
        q = db.query(WebFinding, Scan).join(Scan, WebFinding.scan_id == Scan.id)
        if target_id is not None:
            q = q.filter(Scan.target_id == target_id)
        if scan_ids:
            q = q.filter(WebFinding.scan_id.in_(list(scan_ids)))
        if severities:
            q = q.filter(WebFinding.severity.in_(severities))
        if statuses:
            q = q.filter(WebFinding.status.in_(statuses))
        if host:
            q = q.filter(WebFinding.target_url.ilike(f"%{host}%"))
        if cve_id:
            q = q.filter(WebFinding.cve_id.ilike(f"%{cve_id}%"))
        for w, sc in q.all():
            web_rows.append({
                "scan_id": sc.id, "target": target_label(sc.target_id),
                "target_url": w.target_url, "category": w.category, "name": w.name,
                "severity": w.severity, "cvss": w.cvss_score, "cve_id": w.cve_id,
                "status": w.status, "description": w.description,
                "evidence": w.evidence, "remediation": w.remediation,
                "references": w.references,
            })

    # ---- Package inventory findings ----
    if "package" in want:
        q = db.query(Package, Scan).join(Scan, Package.scan_id == Scan.id)
        if target_id is not None:
            q = q.filter(Scan.target_id == target_id)
        if scan_ids:
            q = q.filter(Package.scan_id.in_(list(scan_ids)))
        if vulnerable_only:
            q = q.filter(Package.status == "vulnerable")
        if severities:
            q = q.filter(Package.max_severity.in_(severities))
        if package:
            q = q.filter(Package.name.ilike(f"%{package}%"))
        if cve_id:
            q = q.filter(Package.cve_ids.ilike(f"%{cve_id}%"))
        for p, sc in q.all():
            pkg_rows.append({
                "scan_id": sc.id, "target": target_label(sc.target_id),
                "name": p.name, "version": p.version, "full_version": p.full_version,
                "manager": p.manager, "status": p.status, "severity": p.max_severity,
                "cvss": p.max_cvss, "cve_count": p.cve_count, "cve_ids": p.cve_ids,
                "remediation": p.remediation,
            })

    sev_weight = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "NONE": 0, "UNKNOWN": 0}
    cve_rows.sort(key=lambda r: (sev_weight.get(r["severity"], 0), r["cvss"] or 0), reverse=True)
    web_rows.sort(key=lambda r: (sev_weight.get(r["severity"], 0), r["cvss"] or 0), reverse=True)
    pkg_rows.sort(key=lambda r: (sev_weight.get(r["severity"], 0), r["cvss"] or 0, r["name"]), reverse=True)

    # severity breakdown across everything included
    breakdown = {}
    for r in (*cve_rows, *web_rows, *pkg_rows):
        sv = r["severity"]
        breakdown[sv] = breakdown.get(sv, 0) + 1

    filters_applied = {
        "target": target_label(target_id) if target_id is not None else "All scans / all targets",
        "severities": sorted(severities) if severities else "any",
        "statuses": sorted(statuses) if statuses else "any",
        "types": sorted(want),
        "host": host or "any", "port": port or "any",
        "cve_id": cve_id or "any", "package": package or "any",
        "confidences": sorted(confidences) if confidences else "any",
        "vulnerable_only": vulnerable_only,
    }
    meta = {
        "filters": filters_applied,
        "counts": {"cve": len(cve_rows), "web": len(web_rows), "package": len(pkg_rows),
                   "total": len(cve_rows) + len(web_rows) + len(pkg_rows)},
        "severity_breakdown": breakdown,
    }
    return {"meta": meta, "cve": cve_rows, "web": web_rows, "package": pkg_rows}
