"""Import CVE data from NVD JSON feeds for offline / air-gapped operation.

Workflow for an air-gapped site:
  1. On an internet-connected machine, download NVD JSON feeds, e.g.
     https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz
     (the legacy 1.1 schema) or NVD API 2.0 JSON exports.
  2. Copy the .json or .json.gz files into ./data/cve_feeds (mounted at /data/cve_feeds).
  3. Trigger an import from the GUI ("CVE Database" -> "Import feeds") or
     POST /api/cves/import.

Both the NVD 1.1 feed schema and the NVD 2.0 API schema are supported.
"""
import glob
import gzip
import json
import lzma
import os
import zlib
from datetime import datetime
from typing import Dict, Iterator, List, Optional, Tuple

from dateutil import parser as dateparser
from sqlalchemy.orm import Session

from ..config import settings
from ..models import CVE


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return dateparser.parse(value).replace(tzinfo=None)
    except (ValueError, TypeError, OverflowError):
        return None


def severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _collect_affected(nodes: List[dict]) -> List[dict]:
    """Walk NVD configuration nodes and extract structured affected ranges.

    Each entry: {"p": product, "v": exactVersion?, "vs": startVer?, "vsi": startIncl?,
                 "ve": endVer?, "vei": endIncl?}. Only entries with an exact version or
                 a version bound are kept (so precise matching is possible).
    """
    out = []

    def walk(node: dict):
        for m in (node.get("cpe_match") or node.get("cpeMatch") or []):
            if m.get("vulnerable") is False:
                continue
            uri = m.get("cpe23Uri") or m.get("criteria") or ""
            parts = uri.split(":")
            if len(parts) < 6:
                continue
            product = parts[4].replace("_", " ").lower().strip()
            if not product or product in ("*", "-"):
                continue
            e = {"p": product}
            exact = parts[5]
            if exact not in ("*", "-", ""):
                e["v"] = exact
            if m.get("versionStartIncluding"):
                e["vs"], e["vsi"] = m["versionStartIncluding"], True
            elif m.get("versionStartExcluding"):
                e["vs"], e["vsi"] = m["versionStartExcluding"], False
            if m.get("versionEndIncluding"):
                e["ve"], e["vei"] = m["versionEndIncluding"], True
            elif m.get("versionEndExcluding"):
                e["ve"], e["vei"] = m["versionEndExcluding"], False
            if "v" in e or "vs" in e or "ve" in e:
                out.append(e)
        for child in node.get("children", []):
            walk(child)

    for n in nodes:
        walk(n)
    return out


def _affected_payload(affected: List[dict]):
    """Return (affected_json, product_name_index) for storage."""
    products = sorted({e["p"] for e in affected})
    return json.dumps(affected[:400]), "|".join(products)[:500]


def _derive_remediation(cve_id: str, refs: List[str], description: str) -> str:
    """Heuristic remediation guidance (offline-friendly, no external lookups)."""
    hints = []
    lowered = (description or "").lower()
    if "buffer overflow" in lowered or "remote code execution" in lowered:
        hints.append("Treat as urgent: apply vendor patch and restrict network exposure.")
    if any(k in lowered for k in ("sql injection", "xss", "cross-site")):
        hints.append("Apply input validation / output encoding and update the affected component.")
    patch_refs = [r for r in refs if any(k in r.lower() for k in ("patch", "advisory", "security", "github", "redhat", "debian", "ubuntu"))]
    base = (
        "Apply the latest vendor security update for the affected product/version. "
        "Where patching is not immediately possible, mitigate by restricting access "
        "to the service, applying network segmentation, and monitoring for exploitation."
    )
    if patch_refs:
        base += " Vendor advisories: " + ", ".join(patch_refs[:3])
    return " ".join(hints + [base])


def _parse_nvd_11_item(item: dict) -> Optional[dict]:
    """Parse one item from the NVD 1.1 feed schema."""
    cve_meta = item.get("cve", {})
    cve_id = cve_meta.get("CVE_data_meta", {}).get("ID")
    if not cve_id:
        return None
    desc = ""
    for d in cve_meta.get("description", {}).get("description_data", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    cwe = ""
    for pt in cve_meta.get("problemtype", {}).get("problemtype_data", []):
        for d in pt.get("description", []):
            if d.get("value", "").startswith("CWE"):
                cwe = d["value"]
                break
    refs = [r.get("url", "") for r in cve_meta.get("references", {}).get("reference_data", []) if r.get("url")]

    impact = item.get("impact", {})
    v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
    v2 = impact.get("baseMetricV2", {}).get("cvssV2", {})
    v3_score = v3.get("baseScore")
    v3_vector = v3.get("vectorString", "")
    v2_score = v2.get("baseScore")
    severity = (v3.get("baseSeverity") or severity_from_score(v3_score or v2_score)).upper()

    affected = _collect_affected(item.get("configurations", {}).get("nodes", []))
    affected_json, product_index = _affected_payload(affected)

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss_v3_score": v3_score,
        "cvss_v3_vector": v3_vector,
        "cvss_v2_score": v2_score,
        "severity": severity,
        "published": _parse_date(item.get("publishedDate")),
        "last_modified": _parse_date(item.get("lastModifiedDate")),
        "cpe_products": product_index,
        "affected": affected_json,
        "references": "\n".join(refs[:30]),
        "remediation": _derive_remediation(cve_id, refs, desc),
        "cwe": cwe,
    }


def _parse_nvd_20_item(cve_meta: dict) -> Optional[dict]:
    """Parse one CVE object in the NVD 2.0 schema.

    Accepts the *cve* object directly (works for both the NVD 2.0 API, where it is
    nested under `vulnerabilities[].cve`, and the fkie-cad mirror, where each
    `cve_items[]` entry is already the cve object).
    """
    cve_id = cve_meta.get("id")
    if not cve_id:
        return None
    desc = ""
    for d in cve_meta.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    refs = [r.get("url", "") for r in cve_meta.get("references", []) if r.get("url")]
    cwe = ""
    for w in cve_meta.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE"):
                cwe = d["value"]
                break

    metrics = cve_meta.get("metrics", {})
    v3_score = v3_vector = v2_score = None
    severity = "UNKNOWN"
    v3_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
    if v3_list:
        data = v3_list[0].get("cvssData", {})
        v3_score = data.get("baseScore")
        v3_vector = data.get("vectorString", "")
        severity = (data.get("baseSeverity") or severity_from_score(v3_score)).upper()
    if metrics.get("cvssMetricV2"):
        v2_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")
        if severity == "UNKNOWN":
            severity = severity_from_score(v2_score)

    affected = []
    for cfg in cve_meta.get("configurations", []):
        affected.extend(_collect_affected(cfg.get("nodes", [])))
    affected_json, product_index = _affected_payload(affected)

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss_v3_score": v3_score,
        "cvss_v3_vector": v3_vector or "",
        "cvss_v2_score": v2_score,
        "severity": severity,
        "published": _parse_date(cve_meta.get("published")),
        "last_modified": _parse_date(cve_meta.get("lastModified")),
        "cpe_products": product_index,
        "affected": affected_json,
        "references": "\n".join(refs[:30]),
        "remediation": _derive_remediation(cve_id, refs, desc),
        "cwe": cwe,
    }


def _open_feed(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if path.endswith(".xz"):
        return lzma.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


def _records_from_file(path: str) -> List[dict]:
    with _open_feed(path) as fh:
        data = json.load(fh)
    records = []
    if "CVE_Items" in data:  # NVD 1.1 legacy feed
        for item in data["CVE_Items"]:
            rec = _parse_nvd_11_item(item)
            if rec:
                records.append(rec)
    elif "vulnerabilities" in data:  # NVD 2.0 API export ({"vulnerabilities":[{"cve":{...}}]})
        for vuln in data["vulnerabilities"]:
            rec = _parse_nvd_20_item(vuln.get("cve", {}))
            if rec:
                records.append(rec)
    elif "cve_items" in data:  # fkie-cad NVD mirror ({"cve_items":[{...cve...}]})
        for item in data["cve_items"]:
            rec = _parse_nvd_20_item(item)
            if rec:
                records.append(rec)
    elif isinstance(data, dict) and isinstance(data.get("cves"), list):
        # ThreatProbe CVE DB export (from another deployment) — see export_cves().
        records = [_normalize_export_record(r) for r in data["cves"]]
        records = [r for r in records if r]
    elif isinstance(data, list):  # plain list of our own CVE dicts (seed format)
        records = [_normalize_export_record(r) for r in data]
        records = [r for r in records if r]
    return records


# Columns that a CVE export/seed record may set (must match the CVE model).
_CVE_FIELDS = (
    "cve_id", "description", "cvss_v3_score", "cvss_v3_vector", "cvss_v2_score",
    "severity", "published", "last_modified", "cpe_products", "affected",
    "references", "remediation", "cwe",
)


def _normalize_export_record(rec: dict) -> Optional[dict]:
    """Coerce an exported/seed CVE dict into a DB-ready record.

    Keeps only known columns and parses ISO date strings back into datetimes so the
    record can be passed straight to CVE(**rec) / upsert.
    """
    if not isinstance(rec, dict) or not rec.get("cve_id"):
        return None
    out = {k: rec[k] for k in _CVE_FIELDS if k in rec}
    for date_key in ("published", "last_modified"):
        val = out.get(date_key)
        if isinstance(val, str):
            out[date_key] = _parse_date(val)
    return out


def export_cves(db: Session, batch: int = 5000) -> Iterator[bytes]:
    """Stream the entire CVE table as a gzip-compressed JSON document.

    Memory stays bounded (rows are streamed with yield_per and gzip-compressed on the
    fly), so this scales to the full multi-hundred-thousand-row database. The output is
    a `{"format": "...", "cves": [ ... ]}` document that import_single_file / the upload
    endpoint and the offline feed importer all understand.
    """
    comp = zlib.compressobj(6, zlib.DEFLATED, 31)  # wbits 31 => gzip container

    def emit(text: str) -> bytes:
        return comp.compress(text.encode("utf-8"))

    head = emit('{"format":"threatprobe-cve-export","version":1,"cves":[')
    if head:
        yield head
    first = True
    for c in db.query(CVE).yield_per(batch):
        rec = {
            "cve_id": c.cve_id, "description": c.description,
            "cvss_v3_score": c.cvss_v3_score, "cvss_v3_vector": c.cvss_v3_vector,
            "cvss_v2_score": c.cvss_v2_score, "severity": c.severity,
            "published": c.published.isoformat() if c.published else None,
            "last_modified": c.last_modified.isoformat() if c.last_modified else None,
            "cpe_products": c.cpe_products, "affected": c.affected,
            "references": c.references, "remediation": c.remediation, "cwe": c.cwe,
        }
        chunk = ("" if first else ",") + json.dumps(rec, separators=(",", ":"))
        first = False
        out = emit(chunk)
        if out:
            yield out
    tail = emit("]}") + comp.flush()
    if tail:
        yield tail


def upsert_records(db: Session, records: List[dict]) -> Tuple[int, int]:
    """Insert or update CVE rows. Returns (imported, updated)."""
    imported = updated = 0
    existing: Dict[str, CVE] = {
        c.cve_id: c
        for c in db.query(CVE).filter(
            CVE.cve_id.in_([r["cve_id"] for r in records])
        ).all()
    }
    for rec in records:
        row = existing.get(rec["cve_id"])
        if row:
            for k, v in rec.items():
                setattr(row, k, v)
            updated += 1
        else:
            db.add(CVE(**rec))
            imported += 1
    db.commit()
    return imported, updated


def import_single_file(db: Session, path: str) -> dict:
    """Import one feed file (used by the online auto-updater)."""
    try:
        records = _records_from_file(path)
    except (json.JSONDecodeError, OSError) as exc:
        return {"imported": 0, "updated": 0, "files_processed": 0,
                "message": f"Failed to read {path}: {exc}"}
    imp = upd = 0
    for i in range(0, len(records), 2000):
        a, b = upsert_records(db, records[i:i + 2000])
        imp += a
        upd += b
    return {"imported": imp, "updated": upd, "files_processed": 1,
            "message": f"{imp} new, {upd} updated from {os.path.basename(path)}."}


def import_feed_directory(db: Session, directory: Optional[str] = None) -> dict:
    """Import every .json/.json.gz feed in the directory."""
    directory = directory or settings.cve_feed_dir
    if not os.path.isdir(directory):
        return {"imported": 0, "updated": 0, "files_processed": 0,
                "message": f"Feed directory {directory} not found"}

    paths = sorted(glob.glob(os.path.join(directory, "*.json")) +
                   glob.glob(os.path.join(directory, "*.json.gz")) +
                   glob.glob(os.path.join(directory, "*.json.xz")))
    total_imp = total_upd = files = 0
    for path in paths:
        try:
            records = _records_from_file(path)
        except (json.JSONDecodeError, OSError) as exc:
            continue
        if not records:
            continue
        # commit in batches to keep memory bounded on large feeds
        for i in range(0, len(records), 2000):
            imp, upd = upsert_records(db, records[i:i + 2000])
            total_imp += imp
            total_upd += upd
        files += 1

    return {
        "imported": total_imp,
        "updated": total_upd,
        "files_processed": files,
        "message": (
            f"Processed {files} feed file(s): {total_imp} new, {total_upd} updated."
            if files else
            f"No feed files found in {directory}. Place NVD JSON feeds there and retry."
        ),
    }
