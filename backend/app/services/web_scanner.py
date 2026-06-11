"""URL / web-application penetration testing (non-destructive).

Checks performed against an authorized target URL:
  - HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy)
  - Information disclosure via Server / X-Powered-By banners (+ CVE correlation)
  - TLS/SSL: certificate validity, expiry, negotiated protocol version
  - Sensitive path exposure (/.git/, /.env, /admin, backup files, etc.)
  - Cookie security flags (Secure, HttpOnly, SameSite)
  - Dangerous HTTP methods (TRACE, PUT, DELETE) via OPTIONS
  - Reflected-input indicator probe (safe, benign canary — flags reflection only)

All checks are read-only / benign. This is intended for authorized assessments.
The standard library only (urllib, ssl, http) is used so it works fully offline
against internal targets with no third-party dependencies.
"""
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

USER_AGENT = "PentestPlatform/1.0 (authorized-assessment)"
TIMEOUT = 15

SECURITY_HEADERS = {
    "strict-transport-security": (
        "Missing HTTP Strict Transport Security (HSTS)", "MEDIUM",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.",
    ),
    "content-security-policy": (
        "Missing Content-Security-Policy (CSP)", "MEDIUM",
        "Define a Content-Security-Policy to mitigate XSS and data-injection attacks.",
    ),
    "x-frame-options": (
        "Missing X-Frame-Options", "LOW",
        "Set 'X-Frame-Options: DENY' or use CSP frame-ancestors to prevent clickjacking.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options", "LOW",
        "Set 'X-Content-Type-Options: nosniff' to prevent MIME sniffing.",
    ),
    "referrer-policy": (
        "Missing Referrer-Policy", "LOW",
        "Set a restrictive Referrer-Policy such as 'strict-origin-when-cross-origin'.",
    ),
    "permissions-policy": (
        "Missing Permissions-Policy", "LOW",
        "Define a Permissions-Policy to restrict access to powerful browser features.",
    ),
}

SENSITIVE_PATHS = [
    ("/.git/HEAD", "Exposed .git repository", "HIGH",
     "Block access to the .git directory; it may leak source code and secrets."),
    ("/.env", "Exposed .env environment file", "CRITICAL",
     "Remove or block access to .env files; they commonly contain credentials."),
    ("/.svn/entries", "Exposed .svn metadata", "HIGH",
     "Block access to version-control metadata directories."),
    ("/admin", "Admin interface reachable", "LOW",
     "Restrict administrative interfaces by IP allow-list / VPN and strong auth."),
    ("/phpinfo.php", "phpinfo() exposed", "MEDIUM",
     "Remove phpinfo() pages; they disclose detailed environment information."),
    ("/server-status", "Apache server-status exposed", "MEDIUM",
     "Restrict mod_status to localhost / trusted IPs."),
    ("/.DS_Store", "Exposed .DS_Store", "LOW",
     "Remove .DS_Store files and block them at the web server."),
    ("/backup.zip", "Backup archive exposed", "HIGH",
     "Remove publicly accessible backup archives."),
    ("/config.php.bak", "Backup of config file exposed", "HIGH",
     "Remove backup copies of configuration files from the web root."),
    ("/.well-known/security.txt", "security.txt present", "INFO",
     "Informational: a security.txt contact policy is published."),
]

DANGEROUS_METHODS = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}


@dataclass
class WebResult:
    findings: List[dict] = field(default_factory=list)
    detected_software: List[str] = field(default_factory=list)  # for CVE correlation
    summary: str = ""

    def add(self, category, name, severity, description, remediation,
            evidence="", references="", cve_id=""):
        self.findings.append({
            "category": category, "name": name, "severity": severity,
            "description": description, "remediation": remediation,
            "evidence": evidence, "references": references, "cve_id": cve_id,
        })


def _normalize_url(raw: str) -> str:
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    return raw


def _request(url: str, method: str = "GET") -> Optional[urllib.response.addinfourl]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we assess certs separately; don't fail closed here
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    try:
        return urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
    except urllib.error.HTTPError as e:
        return e  # HTTPError still carries status + headers
    except (urllib.error.URLError, socket.timeout, ConnectionError, ssl.SSLError, OSError):
        return None


def _check_tls(result: WebResult, host: str, port: int):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto = ssock.version()
                cert = ssock.getpeercert()
    except (socket.timeout, ConnectionError, ssl.SSLError, OSError, socket.gaierror):
        return

    if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        result.add("TLS", f"Weak TLS protocol negotiated ({proto})", "MEDIUM",
                   f"The server negotiated {proto}, which is deprecated.",
                   "Disable TLS 1.1 and earlier; require TLS 1.2+.", evidence=proto)

    if cert:
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.utcnow()).days
                if days < 0:
                    result.add("TLS", "TLS certificate expired", "HIGH",
                               f"The certificate expired on {not_after}.",
                               "Renew the TLS certificate immediately.", evidence=not_after)
                elif days < 30:
                    result.add("TLS", "TLS certificate expiring soon", "LOW",
                               f"The certificate expires on {not_after} ({days} days).",
                               "Renew the TLS certificate before it expires.", evidence=not_after)
            except ValueError:
                pass


def _fingerprint(result: WebResult, headers: Dict[str, str]):
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server:
        result.add("Information Disclosure", "Server banner discloses software", "LOW",
                   f"The Server header reveals software/version: '{server}'.",
                   "Suppress or genericize the Server header to reduce fingerprinting.",
                   evidence=f"Server: {server}")
        result.detected_software.append(server)
    if powered:
        result.add("Information Disclosure", "X-Powered-By discloses technology", "LOW",
                   f"The X-Powered-By header reveals: '{powered}'.",
                   "Remove the X-Powered-By header.", evidence=f"X-Powered-By: {powered}")
        result.detected_software.append(powered)


def _check_cookies(result: WebResult, resp):
    for raw in resp.headers.get_all("Set-Cookie") or []:
        low = raw.lower()
        name = raw.split("=", 1)[0]
        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            result.add("Cookie", f"Cookie '{name}' missing flags: {', '.join(missing)}", "LOW",
                       f"Cookie '{name}' is set without {', '.join(missing)}.",
                       "Set Secure, HttpOnly and SameSite attributes on session cookies.",
                       evidence=raw[:200])


def _check_methods(result: WebResult, base_url: str):
    resp = _request(base_url, method="OPTIONS")
    if resp is None:
        return
    allow = (resp.headers.get("Allow") or resp.headers.get("allow") or "").upper()
    risky = [m for m in DANGEROUS_METHODS if m in allow]
    if risky:
        result.add("Method", f"Dangerous HTTP methods enabled: {', '.join(risky)}", "MEDIUM",
                   f"The server advertises potentially dangerous methods: {', '.join(risky)}.",
                   "Disable unused HTTP methods (TRACE/TRACK/PUT/DELETE).", evidence=f"Allow: {allow}")


def _check_paths(result: WebResult, base: str):
    parsed = urllib.parse.urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"

    # Catch-all guard: probe a random non-existent path. If the server returns 200
    # (e.g. an SPA with `try_files ... /index.html`), then a 200 on a sensitive path
    # means nothing — every path 200s. Use the baseline body length to distinguish
    # real exposures, and skip path checks entirely if we can't.
    baseline = _request(root + "/pt-nonexistent-3f9c2a17-probe")
    baseline_len = None
    if baseline is not None and getattr(baseline, "status", getattr(baseline, "code", 0)) == 200:
        try:
            baseline_len = len(baseline.read(200_000))
        except Exception:
            baseline_len = -1
        result.add("Information Disclosure",
                   "Server returns 200 for unknown paths (SPA / catch-all)", "INFO",
                   "The server responds 200 to non-existent paths, so path-existence "
                   "checks are unreliable and were suppressed to avoid false positives.",
                   "If this is an SPA, ensure sensitive files are still blocked at the web server.",
                   evidence="GET /pt-nonexistent-...-probe -> 200")

    for path, name, severity, remediation in SENSITIVE_PATHS:
        resp = _request(root + path)
        if resp is None:
            continue
        code = getattr(resp, "status", getattr(resp, "code", 0))
        if code != 200:
            continue
        if baseline_len is not None:
            # Catch-all server: only flag if this response clearly differs from baseline.
            try:
                body_len = len(resp.read(200_000))
            except Exception:
                continue
            if baseline_len < 0 or abs(body_len - baseline_len) < 32:
                continue  # same as catch-all -> not a real, distinct file
        sev = severity if name != "security.txt present" else "INFO"
        result.add("Information Disclosure", name, sev,
                   f"{name} — '{path}' returned HTTP 200.", remediation,
                   evidence=f"GET {path} -> 200")


def _check_reflection(result: WebResult, base: str):
    """Benign reflected-input indicator: append a unique canary and see if it echoes.

    Does NOT inject scripts/payloads — only a harmless alphanumeric canary. A reflection
    indicates the parameter is echoed unsanitized and warrants manual XSS testing.
    """
    canary = "ptcanary8714293"
    sep = "&" if urllib.parse.urlparse(base).query else "?"
    test_url = f"{base}{sep}q={canary}"
    resp = _request(test_url)
    if resp is None:
        return
    try:
        body = resp.read(200_000).decode("utf-8", errors="replace")
    except Exception:
        return
    if canary in body:
        result.add("Injection", "Reflected input parameter (potential XSS)", "MEDIUM",
                   "A supplied query parameter was reflected unsanitized in the response body. "
                   "This indicates a possible reflected-XSS sink that warrants manual testing.",
                   "Apply context-aware output encoding and input validation on reflected parameters.",
                   evidence=f"canary '{canary}' reflected from {test_url}")


def run_web_scan(target_url: str) -> WebResult:
    """Run the full non-destructive web assessment against target_url."""
    result = WebResult()
    base = _normalize_url(target_url)
    parsed = urllib.parse.urlparse(base)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    resp = _request(base)
    if resp is None:
        result.summary = f"Target {base} was unreachable."
        result.add("Connectivity", "Target unreachable", "INFO",
                   f"Could not establish an HTTP connection to {base}.",
                   "Verify the URL, network path, and that the service is running.")
        return result

    headers = {k.lower(): v for k, v in resp.headers.items()}
    code = getattr(resp, "status", getattr(resp, "code", 0))

    # Security headers
    for hdr, (name, severity, remediation) in SECURITY_HEADERS.items():
        if hdr not in headers:
            result.add("Security Header", name, severity,
                       f"The response from {base} did not include the {hdr} header.",
                       remediation, evidence=f"HTTP {code}")

    _fingerprint(result, headers)
    _check_cookies(result, resp)
    if parsed.scheme == "https":
        _check_tls(result, host, port)
    else:
        result.add("TLS", "Service served over cleartext HTTP", "MEDIUM",
                   "The target is served over HTTP without transport encryption.",
                   "Serve the application over HTTPS and redirect HTTP to HTTPS.")
    _check_methods(result, base)
    _check_paths(result, base)
    _check_reflection(result, base)

    sev_counts = {}
    for f in result.findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    result.summary = f"Web assessment of {base}: " + ", ".join(
        f"{v} {k}" for k, v in sev_counts.items()) if sev_counts else "No issues found."
    return result
