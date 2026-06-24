"""Periodic CVE database auto-update.

A background scheduler (started by the API) refreshes the local CVE database on an
interval (default every 24h), controlled from the CVE Database page in the GUI.

Two sources:
  - "online":  download the current-year NVD feed from the fkie-cad mirror and import
               it (upsert adds new CVEs and updates modified ones). Needs internet.
  - "feed_dir": re-import whatever feeds are present in the mounted feed directory
               (the air-gapped path — an operator drops new yearly feeds in).

Failures are recorded and never crash the API; in an air-gapped deployment the
online source simply reports an error and the existing data is kept.
"""
import os
import time
import threading
import urllib.request
from datetime import datetime, timedelta

from ..config import settings
from ..database import SessionLocal
from ..models import CveUpdateConfig
from . import cve_import

_MIRROR = "https://github.com/fkie-cad/nvd-json-data-feeds/releases"
_RELEASES_API = "https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/releases/latest"
_AUTO_DIR = "/data/cve_feeds/_auto"


def get_config(db) -> CveUpdateConfig:
    cfg = db.get(CveUpdateConfig, 1)
    if not cfg:
        cfg = CveUpdateConfig(id=1)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _latest_tag() -> str:
    import json
    req = urllib.request.Request(_RELEASES_API, headers={"User-Agent": "ThreatProbe"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["tag_name"]


def _download_current_year() -> str:
    os.makedirs(_AUTO_DIR, exist_ok=True)
    year = datetime.utcnow().year
    tag = _latest_tag()
    url = f"{_MIRROR}/download/{tag}/CVE-{year}.json.xz"
    dest = os.path.join(_AUTO_DIR, f"CVE-{year}.json.xz")
    req = urllib.request.Request(url, headers={"User-Agent": "ThreatProbe"})
    with urllib.request.urlopen(req, timeout=180) as resp, open(dest, "wb") as fh:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            fh.write(chunk)
    return dest


def run_update(db) -> dict:
    """Perform one update run; updates the config row with the outcome."""
    cfg = get_config(db)
    cfg.last_status = "running"
    db.commit()
    try:
        if cfg.source == "online":
            # Keep the downloaded NVD feed on disk (in _auto/) instead of deleting it, so
            # it persists under /data/cve_feeds for air-gap transfer / offline re-import
            # without re-downloading. Re-running overwrites the same CVE-<year>.json.xz.
            path = _download_current_year()
            res = cve_import.import_single_file(db, path)
        else:
            res = cve_import.import_feed_directory(db, settings.cve_feed_dir)
        cfg.last_run = datetime.utcnow()
        cfg.last_status = "ok"
        cfg.last_added = res.get("imported", 0)
        cfg.last_message = res.get("message", "")
        db.commit()
        print(f"[cve-updater] {res.get('message','')}", flush=True)
        return res
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        cfg = get_config(db)
        cfg.last_run = datetime.utcnow()
        cfg.last_status = "error"
        cfg.last_message = str(exc)[:500]
        db.commit()
        print(f"[cve-updater] update failed: {exc}", flush=True)
        return {"imported": 0, "message": f"Update failed: {exc}"}


def _scheduler_loop():
    # Check hourly whether an update is due; run it when enabled and the interval elapsed.
    while True:
        try:
            db = SessionLocal()
            cfg = get_config(db)
            if cfg.enabled:
                due = (cfg.last_run is None or
                       datetime.utcnow() - cfg.last_run >= timedelta(hours=cfg.interval_hours or 24))
                if due:
                    print("[cve-updater] scheduled update due — running", flush=True)
                    run_update(db)
            db.close()
        except Exception as exc:  # noqa: BLE001
            print(f"[cve-updater] scheduler error: {exc}", flush=True)
        time.sleep(3600)  # re-check every hour


def start_scheduler():
    t = threading.Thread(target=_scheduler_loop, daemon=True)
    t.start()
    print("[cve-updater] scheduler started", flush=True)
