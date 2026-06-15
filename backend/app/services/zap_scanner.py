"""OWASP ZAP integration — active/passive web-application scanning.

Drives a headless ZAP daemon via its REST API (stdlib only, no new deps):
  1. Spider the target to discover content.
  2. Wait for passive scanning of discovered requests to drain.
  3. (active mode) Run the active scanner — sends real attack payloads (XSS, SQLi,
     injection, traversal, etc.).
  4. Pull alerts and map them to WebFinding-shaped dicts.

Active scanning is intrusive and must only be run against authorized targets.

Authenticated scanning
----------------------
When a ZapAuth config is supplied, the scan first logs in to the application so
ZAP can reach pages that are only visible to authenticated users (which is where
most real vulnerabilities live). This is done with ZAP's context/authentication
API: a context is created, an authentication method (form / JSON / HTTP) is set,
a user with the supplied credentials is created, and the spider + active scan are
run *as that user* (scanAsUser). A logged-in/out indicator lets ZAP detect session
expiry and re-authenticate mid-scan. Credentials are passed in-memory only and are
never persisted.
"""
import json
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

from ..config import settings

# ZAP risk -> our severity
_RISK_SEV = {"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Informational": "INFO"}


@dataclass
class ZapAuth:
    """Authentication config for a credentialed (deeper) ZAP scan.

    auth_type:
      form  - form-based login (POST username/password to login_url)
      json  - JSON login (POST a JSON body to login_url) — common for SPAs/APIs
      http  - HTTP/NTLM Basic authentication (no login form)
    """
    auth_type: str = "form"               # form | json | http
    username: str = ""
    password: str = ""
    login_url: str = ""                   # where the login request is sent (form/json)
    username_field: str = "username"      # form/json field name for the username
    password_field: str = "password"      # form/json field name for the password
    extra_post_data: str = ""             # extra "k=v&k2=v2" appended to the login body
    logged_in_regex: str = ""             # regex matching a logged-IN response (e.g. "Logout")
    logged_out_regex: str = ""            # regex matching a logged-OUT response (e.g. "Login")

    def configured(self) -> bool:
        if not self.username:
            return False
        if self.auth_type in ("form", "json"):
            return bool(self.login_url)
        return True  # http basic just needs credentials


@dataclass
class ZapResult:
    findings: List[dict] = field(default_factory=list)
    summary: str = ""
    urls_found: int = 0
    authenticated: bool = False

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


def _set_scope_limits():
    """Bound the crawl and active scan so memory stays finite on real/large sites."""
    calls = [
        ("/JSON/spider/action/setOptionMaxDepth/", {"Integer": settings.zap_spider_max_depth}),
        ("/JSON/spider/action/setOptionMaxDuration/", {"Integer": settings.zap_spider_max_minutes}),
        ("/JSON/spider/action/setOptionThreadCount/", {"Integer": 2}),
        ("/JSON/ascan/action/setOptionMaxScanDurationInMins/", {"Integer": settings.zap_active_max_minutes}),
        ("/JSON/ascan/action/setOptionThreadPerHost/", {"Integer": 2}),
        ("/JSON/ascan/action/setOptionHostPerScan/", {"Integer": 1}),
        ("/JSON/ascan/action/setOptionMaxResultsToList/", {"Integer": 200}),
    ]
    for path, params in calls:
        try:
            _api(path, params, timeout=15)
        except Exception:
            pass  # option names vary slightly by ZAP version; best-effort


def _context_regex(url: str) -> str:
    """Regex matching the target's origin (scheme+host[:port]) and everything under it."""
    p = urllib.parse.urlparse(url)
    origin = f"{p.scheme}://{p.netloc}"
    return re.escape(origin) + ".*"


def _setup_auth(url: str, auth: "ZapAuth", log) -> Optional[tuple]:
    """Create a ZAP context + authenticated user for `url`.

    Returns (context_id, user_id) on success, or None if setup failed (the caller
    then falls back to an unauthenticated scan).
    """
    try:
        ctx = _api("/JSON/context/action/newContext/", {"contextName": "auth-scan"})
        context_id = ctx.get("contextId")
        _api("/JSON/context/action/includeInContext/",
             {"contextName": "auth-scan", "regex": _context_regex(url)})

        if auth.auth_type in ("form", "json"):
            method = "formBasedAuthentication" if auth.auth_type == "form" else "jsonBasedAuthentication"
            if auth.auth_type == "json":
                body = json.dumps({auth.username_field: "{%username%}",
                                   auth.password_field: "{%password%}"})
            else:
                body = f"{auth.username_field}={{%username%}}&{auth.password_field}={{%password%}}"
            if auth.extra_post_data:
                # form: append as query params; json: ZAP only templates the body, so skip.
                if auth.auth_type == "form":
                    body = f"{body}&{auth.extra_post_data}"
            cfg = ("loginUrl=" + urllib.parse.quote(auth.login_url, safe="") +
                   "&loginRequestData=" + urllib.parse.quote(body, safe=""))
            _api("/JSON/authentication/action/setAuthenticationMethod/",
                 {"contextId": context_id, "authMethodName": method,
                  "authMethodConfigParams": cfg})
        else:  # http basic / NTLM
            p = urllib.parse.urlparse(auth.login_url or url)
            cfg = ("hostname=" + urllib.parse.quote(p.hostname or "", safe="") +
                   "&realm=&port=" + str(p.port or (443 if p.scheme == "https" else 80)))
            _api("/JSON/authentication/action/setAuthenticationMethod/",
                 {"contextId": context_id, "authMethodName": "httpAuthentication",
                  "authMethodConfigParams": cfg})

        if auth.logged_in_regex:
            _api("/JSON/authentication/action/setLoggedInIndicator/",
                 {"contextId": context_id, "loggedInIndicatorRegex": auth.logged_in_regex})
        if auth.logged_out_regex:
            _api("/JSON/authentication/action/setLoggedOutIndicator/",
                 {"contextId": context_id, "loggedOutIndicatorRegex": auth.logged_out_regex})

        user = _api("/JSON/users/action/newUser/",
                    {"contextId": context_id, "name": "scan-user"})
        user_id = user.get("userId")
        creds = ("username=" + urllib.parse.quote(auth.username, safe="") +
                 "&password=" + urllib.parse.quote(auth.password, safe=""))
        _api("/JSON/users/action/setAuthenticationCredentials/",
             {"contextId": context_id, "userId": user_id, "authCredentialsConfigParams": creds})
        _api("/JSON/users/action/setUserEnabled/",
             {"contextId": context_id, "userId": user_id, "enabled": "true"})
        # Force all traffic (incl. passive proxying) to use this user's session.
        try:
            _api("/JSON/forcedUser/action/setForcedUser/",
                 {"contextId": context_id, "userId": user_id})
            _api("/JSON/forcedUser/action/setForcedUserModeEnabled/", {"boolean": "true"})
        except Exception:
            pass
        log(f"Authentication configured ({auth.auth_type}) for user '{auth.username}'.")
        return context_id, user_id
    except Exception as exc:  # noqa: BLE001
        log(f"Authentication setup failed ({exc}); falling back to unauthenticated scan.")
        return None


def _spider(url: str, deadline: float, ctx: Optional[tuple] = None) -> int:
    if ctx:
        scan_id = _api("/JSON/spider/action/scanAsUser/",
                       {"contextId": ctx[0], "userId": ctx[1], "url": url, "recurse": "true",
                        "maxChildren": str(settings.zap_spider_max_children)}).get("scanAsUser")
    else:
        scan_id = _api("/JSON/spider/action/scan/",
                       {"url": url, "recurse": "true",
                        "maxChildren": str(settings.zap_spider_max_children)}).get("scan")
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


def _active(url: str, deadline: float, ctx: Optional[tuple] = None):
    if ctx:
        scan_id = _api("/JSON/ascan/action/scanAsUser/",
                       {"contextId": ctx[0], "userId": ctx[1], "url": url, "recurse": "true"},
                       timeout=60).get("scanAsUser")
    else:
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


def run_zap_scan(target_url: str, active: bool = False, log_cb=None,
                 auth: "Optional[ZapAuth]" = None) -> ZapResult:
    """Run a ZAP spider+passive (and optional active) scan; return mapped findings.

    If `auth` is supplied and configured, the scan logs in first and crawls/attacks
    the target as the authenticated user for deeper coverage.
    """
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
    _set_scope_limits()
    _log(f"Scope bounded: spider depth≤{settings.zap_spider_max_depth}, "
         f"≤{settings.zap_spider_max_children} children/node, active ≤{settings.zap_active_max_minutes} min")
    # Seed ZAP with the target so it's in scope / accessed at least once.
    try:
        _api("/JSON/core/action/accessUrl/", {"url": url, "followRedirects": "true"}, timeout=60)
    except Exception:
        pass

    # Configure authentication (deeper scan) if credentials were supplied.
    ctx = None
    if auth is not None and auth.configured():
        _log(f"Setting up authenticated scan as '{auth.username}'…")
        ctx = _setup_auth(url, auth, _log)
        result.authenticated = ctx is not None

    _log(f"Spidering {url} (max {settings.zap_spider_max_minutes} min"
         f"{', authenticated' if ctx else ''})…")
    spider_deadline = time.time() + settings.zap_spider_max_minutes * 60
    result.urls_found = _spider(url, spider_deadline, ctx)
    _log(f"Spider done: {result.urls_found} URL(s) discovered. Draining passive scan…")
    _wait_passive(spider_deadline + 120)

    if active:
        _log(f"Active scan started (intrusive; max {settings.zap_active_max_minutes} min"
             f"{', authenticated' if ctx else ''})…")
        active_deadline = time.time() + settings.zap_active_max_minutes * 60
        _active(url, active_deadline, ctx)
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
    auth_note = " (authenticated)" if result.authenticated else ""
    result.summary = (f"ZAP {mode}{auth_note} scan of {url}: {result.urls_found} URLs crawled, "
                      f"{len(result.findings)} alerts (" +
                      ", ".join(f"{v} {k}" for k, v in counts.items()) + ").")
    return result
