"""Threat-intel enrichment for the local CVE database: CISA KEV + FIRST EPSS.

Both sources are small and downloadable, so they work air-gapped: drop the files in
the feed directory (or let the online fetch pull them on a connected host).

  - CISA KEV  (Known Exploited Vulnerabilities) — CVEs known to be exploited in the
    wild. JSON: {"vulnerabilities": [{"cveID": "...", "dateAdded": "YYYY-MM-DD", ...}]}.
    File: known_exploited_vulnerabilities.json  (or kev*.json in the feed dir).
  - FIRST EPSS (Exploit Prediction Scoring System) — probability a CVE will be
    exploited in the next 30 days. CSV (often .gz) with a model-version comment line,
    then header `cve,epss,percentile`, then rows.
    File: epss_scores-current.csv[.gz]  (or epss*.csv[.gz] in the feed dir).

Enrichment only UPDATES existing CVE rows (it never creates CVEs), so import NVD feeds
first, then enrich.
"""
import csv
import glob
import gzip
import io
import json
import os
import urllib.request
from datetime import datetime
from typing import Optional

from sqlalchemy import update
from sqlalchemy.orm import Session

from ..config import settings
from ..models import CVE

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

_KEV_GLOBS = ("known_exploited_vulnerabilities.json", "kev*.json", "*kev*.json")
_EPSS_GLOBS = ("epss_scores-current.csv.gz", "epss*.csv.gz", "epss*.csv", "*epss*.csv*")


def _find_one(directory: str, patterns) -> Optional[str]:
    for pat in patterns:
        hits = sorted(glob.glob(os.path.join(directory, pat)))
        if hits:
            return hits[0]
    return None


def _save(directory: str, filename: str, data: bytes) -> Optional[str]:
    """Persist a downloaded feed into the (host-mounted, persistent) feed dir.

    Lets a connected host produce the exact files an air-gapped host needs: copy
    the feed dir across and re-import offline. Best-effort — a write failure must
    not abort the in-memory import that just succeeded.
    """
    try:
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, filename)
        with open(path, "wb") as fh:
            fh.write(data)
        return path
    except OSError:
        return None


def _parse_kev_date(value: str) -> Optional[datetime]:
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt)
        except (ValueError, TypeError):
            continue
    return None


def import_kev_data(db: Session, data: dict) -> int:
    """Mark CVEs present in a parsed KEV catalog. Returns how many local rows updated."""
    vulns = data.get("vulnerabilities") or []
    by_id = {}
    for v in vulns:
        cid = (v.get("cveID") or v.get("cveId") or "").strip().upper()
        if cid:
            by_id[cid] = _parse_kev_date(v.get("dateAdded", ""))
    if not by_id:
        return 0
    updated = 0
    ids = list(by_id)
    for i in range(0, len(ids), 1000):
        chunk = ids[i:i + 1000]
        rows = db.query(CVE).filter(CVE.cve_id.in_(chunk)).all()
        for row in rows:
            row.kev = True
            row.kev_date = by_id.get(row.cve_id)
            updated += 1
        db.commit()
    return updated


def import_epss_rows(db: Session, reader) -> int:
    """Apply EPSS score/percentile to existing CVE rows from a csv reader. Returns count."""
    # Buffer into a dict so we batch DB updates (the EPSS file has ~250k rows).
    scores = {}
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if row[0].strip().lower() == "cve":  # header
            continue
        if len(row) < 3:
            continue
        cid = row[0].strip().upper()
        try:
            scores[cid] = (float(row[1]), float(row[2]))
        except ValueError:
            continue
    if not scores:
        return 0
    updated = 0
    ids = list(scores)
    for i in range(0, len(ids), 1000):
        chunk = ids[i:i + 1000]
        rows = db.query(CVE).filter(CVE.cve_id.in_(chunk)).all()
        for row in rows:
            sc, pct = scores[row.cve_id]
            row.epss_score, row.epss_percentile = sc, pct
            updated += 1
        db.commit()
    return updated


def _open_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


def import_threat_intel(db: Session, directory: Optional[str] = None,
                        online: bool = False) -> dict:
    """Import KEV + EPSS from the feed directory (or fetch online). Enriches existing CVEs."""
    directory = directory or settings.cve_feed_dir
    kev_updated = epss_updated = 0
    messages = []

    # ---- KEV ----
    try:
        if online:
            req = urllib.request.Request(KEV_URL, headers={"User-Agent": "ThreatProbe"})
            with urllib.request.urlopen(req, timeout=120) as r:
                raw = r.read()
            # Save into the persistent feed dir so this file can be copied to an
            # air-gapped host and re-imported there (offline) without re-downloading.
            _save(directory, "known_exploited_vulnerabilities.json", raw)
            kev_updated = import_kev_data(db, json.loads(raw.decode("utf-8", errors="replace")))
        else:
            path = _find_one(directory, _KEV_GLOBS)
            if path:
                with _open_text(path) as fh:
                    kev_updated = import_kev_data(db, json.load(fh))
            else:
                messages.append("no KEV file found")
        if kev_updated or online:
            messages.append(f"KEV: {kev_updated} CVE(s) flagged exploited")
    except Exception as exc:  # noqa: BLE001
        messages.append(f"KEV import failed: {exc}")

    # ---- EPSS ----
    try:
        if online:
            req = urllib.request.Request(EPSS_URL, headers={"User-Agent": "ThreatProbe"})
            with urllib.request.urlopen(req, timeout=180) as r:
                gz = r.read()
            # Persist the raw .gz for air-gap transfer, then decompress for this import.
            _save(directory, "epss_scores-current.csv.gz", gz)
            raw = gzip.decompress(gz).decode("utf-8", errors="replace")
            epss_updated = import_epss_rows(db, csv.reader(io.StringIO(raw)))
        else:
            path = _find_one(directory, _EPSS_GLOBS)
            if path:
                with _open_text(path) as fh:
                    epss_updated = import_epss_rows(db, csv.reader(fh))
            else:
                messages.append("no EPSS file found")
        if epss_updated or online:
            messages.append(f"EPSS: {epss_updated} CVE(s) scored")
    except Exception as exc:  # noqa: BLE001
        messages.append(f"EPSS import failed: {exc}")

    return {
        "kev_updated": kev_updated,
        "epss_updated": epss_updated,
        "message": "; ".join(messages) or "Nothing to import.",
    }
