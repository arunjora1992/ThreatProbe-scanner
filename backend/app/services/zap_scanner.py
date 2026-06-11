"""OWASP ZAP integration — active/passive web-application scanning.

Drives a headless ZAP daemon via its REST API (stdlib only, no new deps):
  1. Spider the target to discover content.
  2. Wait for passive scanning of discovered requests to drain.
  3. (active mode) Run the active scanner — sends real attack payloads (XSS, SQLi,
     injection, traversal, etc.).
  4. Pull alerts and map them to WebFinding-shaped dicts.

Active scanning is intrusive and must only be run against authorized targets.
"""
import json
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

from ..config import settings

# ZAP risk -> our severity
_RISK_SEV = {"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Informational": "INFO"}


@dataclass
class ZapResult:
    findings: List[dict] = field(default_factory=list)
    summary: str = ""
    urls_found: int = 0

    def add(self, **kw):
        self.findings.append(kw)


def _normalize_url(raw: str) -> str:
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    return raw


def _api(path: str, params: dict = None, timeout: int = 60):
    """Call a ZAP JSON API endpoint and return the parsed dict."""
    params = dict(params or {})
    if settings.zap_api_key:
        params["apikey"] = settings.zap_api_key
    qs = urllib.parse.urlencode(params)
    url = f"{settings.zap_api_url}{path}"
    if qs:
        url += f"?{qs}"
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def zap_available() -> bool:
    try:
        _api("/JSON/core/view/version/", timeout=10)
        return True
    except Exception:
        return False


def wait_for_zap(retries: int = 30, delay: float = 3.0) -> bool:
    for _ in range(retries):
        if zap_available():
            return True
        time.sleep(delay)
    return False


def _spider(url: str, deadline: float) -> int:
    scan_id = _api("/JSON/spider/action/scan/",
                   {"url": url, "recurse": "true", "maxChildren": "0"}).get("scan")
    while time.time() < deadline:
        status = _api("/JSON/spider/view/status/", {"scanId": scan_id}).get("status", "0")
        if status == "100":
            break
        time.sleep(3)
    try:
        results = _api("/JSON/spider/view/results/", {"scanId": scan_id}).get("results", [])
        return len(results)
    except Exception:
        return 0


def _wait_passive(deadline: float):
    while time.time() < deadline:
        try:
            rec = _api("/JSON/pscan/view/recordsToScan/").get("recordsToScan", "0")
        except Exception:
            return
        if rec in ("0", 0):
            return
        time.sleep(2)


def _active(url: str, deadline: float):
    scan_id = _api("/JSON/ascan/action/scan/",
                   {"url": url, "recurse": "true", "inScopeOnly": "false"},
                   timeout=60).get("scan")
    while time.time() < deadline:
        status = _api("/JSON/ascan/view/status/", {"scanId": scan_id}).get("status", "0")
        if status == "100":
            break
        time.sleep(5)


def _collect_alerts(url: str) -> List[dict]:
    out, start, count = [], 0, 500
    while True:
        batch = _api("/JSON/core/view/alerts/",
                     {"baseurl": url, "start": start, "count": count}).get("alerts", [])
        if not batch:
            break
        out.extend(batch)
        if len(batch) < count:
            break
        start += count
    return out


def _map_alert(a: dict) -> dict:
    risk = (a.get("risk") or "Informational").split(" ")[0]
    severity = _RISK_SEV.get(risk, "INFO")
    cwe = a.get("cweid", "")
    cwe = f"CWE-{cwe}" if cwe and cwe not in ("-1", "0") else ""
    name = a.get("alert") or a.get("name") or "ZAP alert"
    desc = a.get("description", "")
    if a.get("param"):
        desc = f"{desc}\nParameter: {a['param']}"
    if cwe:
        desc = f"{desc}\n{cwe}"
    return {
        "category": "ZAP",
        "name": name,
        "severity": severity,
        "cve_id": "",
        "description": desc.strip(),
        "evidence": (a.get("evidence") or "")[:500] + (f"  [{a.get('url','')}]" if a.get("url") else ""),
        "remediation": a.get("solution", ""),
        "references": a.get("reference", ""),
    }


def run_zap_scan(target_url: str, active: bool = False, log_cb=None) -> ZapResult:
    """Run a ZAP spider+passive (and optional active) scan; return mapped findings."""
    def _log(m):
        if log_cb:
            log_cb(m)
    result = ZapResult()
    _log("Connecting to ZAP daemon…")
    if not wait_for_zap():
        result.summary = "ZAP daemon is not reachable."
        result.add(category="ZAP", name="ZAP engine unavailable", severity="INFO",
                   cve_id="", description="Could not reach the ZAP daemon API.",
                   evidence=settings.zap_api_url,
                   remediation="Ensure the 'zap' service is running.", references="")
        return result

    url = _normalize_url(target_url)
    # Start a fresh session so each scan's data is bounded (and old session files are
    # released) — important on disk-constrained hosts.
    try:
        _api("/JSON/core/action/newSession/", {"name": "scan", "overwrite": "true"}, timeout=60)
    except Exception:
        pass
    # Seed ZAP with the target so it's in scope / accessed at least once.
    try:
        _api("/JSON/core/action/accessUrl/", {"url": url, "followRedirects": "true"}, timeout=60)
    except Exception:
        pass

    _log(f"Spidering {url} (max {settings.zap_spider_max_minutes} min)…")
    spider_deadline = time.time() + settings.zap_spider_max_minutes * 60
    result.urls_found = _spider(url, spider_deadline)
    _log(f"Spider done: {result.urls_found} URL(s) discovered. Draining passive scan…")
    _wait_passive(spider_deadline + 120)

    if active:
        _log(f"Active scan started (intrusive; max {settings.zap_active_max_minutes} min)…")
        active_deadline = time.time() + settings.zap_active_max_minutes * 60
        _active(url, active_deadline)
        _log("Active scan complete. Draining passive scan…")
        _wait_passive(time.time() + 60)
    _log("Collecting alerts…")

    # Collapse ZAP's per-URL instances into one finding per (alert type, severity),
    # recording how many URLs were affected.
    seen = {}
    for a in _collect_alerts(url):
        f = _map_alert(a)
        key = (f["name"], f["severity"])
        if key in seen:
            seen[key]["count"] += 1
            continue
        f["count"] = 1
        seen[key] = f
    for f in seen.values():
        if f["count"] > 1:
            f["description"] = f"{f['description']}\n(Affected {f['count']} URLs/instances.)"
        f.pop("count", None)
        result.findings.append(f)

    counts = {}
    for f in result.findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    mode = "active" if active else "passive"
    result.summary = (f"ZAP {mode} scan of {url}: {result.urls_found} URLs crawled, "
                      f"{len(result.findings)} alerts (" +
                      ", ".join(f"{v} {k}" for k, v in counts.items()) + ").")
    return result
