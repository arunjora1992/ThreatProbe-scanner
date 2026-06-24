"""Offline AI assistant — RAG-grounded chat over the local CVE DB and scan results.

A small local model (llama.cpp server, OpenAI-compatible API) must NEVER recall security
facts on its own — a 1.5B model will happily invent CVE IDs, CVSS scores and "fixes".
So the backend does the knowing and the model does the explaining:

  1. retrieve(): detect entities in the user's message (CVE IDs, "scan #N", a package
     name, a vuln-class keyword) and pull authoritative facts from the local database.
  2. answer(): hand those facts to the model as CONTEXT and instruct it to answer using
     only them. If the model server is unreachable, a deterministic summary of the
     retrieved facts is returned, so the assistant still works without the model.

This keeps answers accurate, citeable, and fully offline.
"""
import json
import re
import urllib.error
import urllib.request

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..config import settings
from ..models import (CVE, ConfigFinding, DistroAdvisory, Finding, Host, Package,
                      Scan, Service, Target, WebFinding)
from . import version_compare

CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
FIXPLAN_RE = re.compile(
    r"(fix plan|patch plan|remediation plan|remediation steps|action plan|fix first|"
    r"patch first|what should i (fix|patch|remediat)|what to (fix|patch|remediat)|"
    r"prioriti[sz])\w*", re.I)
DIFF_RE = re.compile(
    r"\b(compare|diff|difference|what changed|changed since|since (the )?(last|previous) "
    r"scan|\bvs\b|versus)\b", re.I)
SCAN_RE = re.compile(r"scan\s*#?\s*(\d+)", re.I)
PKG_RE = re.compile(r"(?:package|is|about)\s+([a-zA-Z0-9][\w.+-]{1,40})", re.I)
_PKG_STOP = {"the", "this", "it", "there", "vulnerable", "any", "a", "an", "my", "all",
             "package", "which", "what", "some", "that", "found", "for", "of", "in", "on"}


def _extract_package(message: str):
    """Pull a package name from varied phrasings: 'CVE(s) for kernel', 'kernel CVEs',
    'package kernel', 'is openssl vulnerable', 'about glibc'."""
    s = message.strip()
    for rx in (r"\bcves?\s+(?:for|of|in|on|about|affecting)\s+([a-zA-Z0-9][\w.+-]{1,40})",
               r"\b(?:package|pkg|is|about|patch|update)\s+([a-zA-Z0-9][\w.+-]{1,40})",
               r"\b([a-zA-Z0-9][\w.+-]{1,40})\s+(?:package\s+)?(?:cves?|vulnerab\w*|advisor\w*)"):
        m = re.search(rx, s, re.I)
        if m and m.group(1).lower() not in _PKG_STOP:
            return m.group(1)
    return None
HOST_RE = re.compile(r"https?://([^/\s]+)|\b(\d{1,3}(?:\.\d{1,3}){3})\b|\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)
# Stems (no trailing \b) so "summarise", "vulnerability", "findings", "scanning" all match.
SCAN_INTENT_RE = re.compile(
    r"\b(scan|result|audit|finding|vulnerab|compliance|report|assessment|summar|show)\w*", re.I)
# A pointed sub-question about a scan (vs. a plain "summarise it") -> let the model answer
# the specific question from the scan facts, instead of dumping the whole summary.
SPECIFIC_RE = re.compile(
    r"\b(critical|high|medium|\blow\b|sever|remediat|\bfix|which|where|"
    r"host|port|service|packag|kev|exploit|epss|cvss|web|url|failed|\bfail|\bpass|control|"
    r"\btop\b|worst|detail|recommend|priorit|open port|patch|cwe)\w*", re.I)
# Count/how-many questions are answered deterministically (the model miscounts) — the
# deterministic summary already states the exact totals + severity breakdown.
COUNT_RE = re.compile(r"how many|how much|number of|\bcount\b|\btotal\b", re.I)


def _extract_host(message: str):
    m = HOST_RE.search(message or "")
    return next((g for g in m.groups() if g), None) if m else None

# Grounded explanations for common vuln classes (so "explain X" is accurate regardless
# of the small model). keyword(s) -> (title, what, fix).
VULN_CLASS_DOCS = {
    "xss": ("Cross-Site Scripting (XSS)",
            "Untrusted input is reflected into a page so a victim's browser executes attacker-controlled script, enabling session theft, keylogging and account takeover.",
            "Context-aware output encoding, a strict Content-Security-Policy, HttpOnly cookies, and framework auto-escaping. Validate/normalise input."),
    "sql": ("SQL Injection (SQLi)",
            "Untrusted input is concatenated into a SQL query, letting an attacker read/modify the database or bypass auth.",
            "Use parameterised queries / prepared statements (never string-concatenate SQL), least-privilege DB accounts, and input validation."),
    "csrf": ("Cross-Site Request Forgery (CSRF)",
             "A logged-in user's browser is tricked into sending a state-changing request they didn't intend.",
             "Anti-CSRF tokens (synchroniser/double-submit), SameSite=Lax/Strict cookies, and re-auth for sensitive actions."),
    "ssrf": ("Server-Side Request Forgery (SSRF)",
             "The server is coerced into making requests to attacker-chosen URLs, often reaching internal services or cloud metadata.",
             "Allowlist outbound hosts, block link-local/metadata ranges (169.254.169.254), disable unused URL schemes, and validate user-supplied URLs."),
    "idor": ("Insecure Direct Object Reference (IDOR)",
             "An object identifier in a request can be changed to access another user's data because authorization isn't enforced server-side.",
             "Enforce per-object authorization on every request; prefer unguessable IDs; never trust client-supplied identifiers."),
    "rce": ("Remote Code Execution (RCE)",
            "An attacker runs arbitrary code on the server — usually the most severe outcome.",
            "Patch the affected component, avoid passing input to shells/eval, sandbox, and apply least privilege."),
    "traversal": ("Path Traversal / LFI",
                  "Manipulating a file path (../) lets an attacker read or include files outside the intended directory.",
                  "Canonicalise and validate paths against an allowlist; never pass user input directly to file APIs."),
    "redirect": ("Open Redirect",
                 "An app redirects to a user-controlled URL, aiding phishing and OAuth token theft.",
                 "Allowlist redirect targets or use server-side mapping keys instead of full URLs."),
    "clickjack": ("Clickjacking",
                  "The site is framed by a malicious page to trick users into clicking hidden elements.",
                  "Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors 'none'."),
    "csp": ("Missing Content-Security-Policy",
            "Without CSP the browser has no policy limiting where scripts/resources load from, increasing XSS impact.",
            "Add a restrictive Content-Security-Policy (e.g. default-src 'self'); avoid 'unsafe-inline'."),
    "hsts": ("Missing HSTS",
             "Without Strict-Transport-Security a user can be downgraded to HTTP and MITM'd.",
             "Add Strict-Transport-Security: max-age=31536000; includeSubDomains (preload once verified)."),
    "tls": ("Weak TLS / SSL",
            "Obsolete protocols (SSLv3/TLS1.0/1.1) or weak ciphers allow decryption/MITM.",
            "Enable only TLS 1.2+/1.3, disable weak ciphers/RC4/3DES, use strong key exchange (ECDHE)."),
    "cors": ("Misconfigured CORS",
             "Over-permissive CORS (e.g. reflecting Origin with credentials) lets malicious sites read authenticated responses.",
             "Allowlist trusted origins; never combine Access-Control-Allow-Origin: * with credentials."),
    "header": ("Missing security headers",
               "Absent headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options) weaken browser-side defenses.",
               "Add CSP, HSTS, X-Content-Type-Options: nosniff, X-Frame-Options, and Referrer-Policy."),
    "cis": ("CIS hardening finding",
            "A host configuration deviates from the CIS Benchmark (e.g. SSH root login, weak password policy, missing auditd).",
            "Apply the control's remediation from the scan, then re-run the CIS scan to confirm compliance."),
}


def _http_json(url: str, payload: dict, timeout: int):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def llm_available() -> bool:
    try:
        req = urllib.request.Request(f"{settings.llm_api_url}/health")
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


def _chat_llm(messages: list) -> str:
    resp = _http_json(
        f"{settings.llm_api_url}/v1/chat/completions",
        {"model": settings.llm_model, "messages": messages,
         "temperature": 0.2, "max_tokens": 600, "stream": False},
        timeout=settings.llm_timeout_seconds,
    )
    return (resp.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()


def _cve_block(c: CVE) -> str:
    bits = [f"{c.cve_id}: severity {c.severity or '?'}, CVSS {c.cvss_v3_score if c.cvss_v3_score is not None else c.cvss_v2_score}"]
    if c.kev:
        bits.append("ACTIVELY EXPLOITED (CISA KEV)")
    if c.epss_score is not None:
        bits.append(f"EPSS {c.epss_score * 100:.1f}%")
    if c.cwe:
        bits.append(f"CWE {c.cwe}")
    head = " | ".join(bits)
    desc = (c.description or "").strip().replace("\n", " ")
    rem = (c.remediation or "").strip().replace("\n", " ")
    out = f"{head}\nDescription: {desc[:600]}"
    if rem:
        out += f"\nRemediation: {rem[:300]}"
    return out


def retrieve(db: Session, message: str) -> dict:
    """Pull authoritative facts for entities mentioned in the message."""
    blocks, citations = [], []
    scan_summary = None
    resolved_scan = None

    # ---- CVE IDs ----
    for cid in dict.fromkeys(m.upper() for m in CVE_RE.findall(message)):
        c = db.query(CVE).filter(func.upper(CVE.cve_id) == cid).first()
        if c:
            blocks.append("[CVE] " + _cve_block(c))
            citations.append(c.cve_id)
        else:
            blocks.append(f"[CVE] {cid}: not present in the local CVE database.")

    # ---- scan: explicit '#N', by target IP/host, or a bare number with scan intent ----
    # (Deterministic — a small model misreads aggregate counts.) CVE digits and IP octets
    # are excluded so e.g. "scan result of 89" -> scan #89, not a target IP.
    scan = None
    note = ""
    sm = SCAN_RE.search(message)
    if sm:
        sid = int(sm.group(1))
        scan = db.get(Scan, sid)
        if not scan:
            blocks.append(f"[SCAN] Scan #{sid} not found in the database.")
            scan_summary = f"I have no record of scan #{sid} in the database."
    elif SCAN_INTENT_RE.search(message):
        host = _extract_host(message)
        if host:
            from ..models import Target
            target = (db.query(Target)
                      .filter(func.lower(Target.address).like(f"%{host.lower()}%")).first())
            if target:
                scan = (db.query(Scan).filter(Scan.target_id == target.id)
                        .order_by(Scan.created_at.desc()).first())
                note = f" (latest scan for {host})"
        if scan is None and not CVE_RE.search(message):
            # a standalone integer not embedded in an IP/CVE -> a scan id
            nm = re.search(r"(?<![\d.\-])(\d{1,6})(?![\d.\-])", message)
            if nm:
                scan = db.get(Scan, int(nm.group(1)))
                if not scan:
                    scan_summary = f"I have no record of scan #{int(nm.group(1))} in the database."
    if scan is not None and scan_summary is None:
        resolved_scan = scan
        citations.append(f"scan#{scan.id}")
        scan_summary = _scan_summary(db, scan)
        blocks.append(f"[SCAN]{note} " + scan_summary.replace("\n", " "))

    # ---- package CVE lookup (deterministic) ----
    pkg_summary = None
    if not citations:  # only if nothing more specific matched
        name = _extract_package(message)
        if name:
            pkg_summary = _package_summary(db, name)
            if pkg_summary:
                citations.append(name)
                blocks.append("[PACKAGE] " + pkg_summary.replace("\n", " "))

    # ---- vuln-class education ----
    low = message.lower()
    seen = set()
    for kw, (title, what, fix) in VULN_CLASS_DOCS.items():
        if kw in low and title not in seen:
            seen.add(title)
            blocks.append(f"[CLASS] {title}: {what} Fix: {fix}")

    return {"blocks": blocks, "citations": list(dict.fromkeys(citations)),
            "scan_summary": scan_summary, "pkg_summary": pkg_summary,
            "scan_id": resolved_scan.id if resolved_scan else None,
            "scan_context": _scan_context(db, resolved_scan) if resolved_scan else None}


def _package_summary(db: Session, name: str) -> str:
    """Deterministic CVE summary for a package: known CVEs in the local CVE DB (by affected
    product, with a kernel→linux_kernel alias) + distro advisories (backport-aware fixes)."""
    nl = name.lower()
    products = {nl}
    if nl == "kernel" or nl.startswith("kernel"):
        products.add("linux_kernel")
    conds = [func.lower(CVE.cpe_products).like(f"%{p}%") for p in products]
    base = db.query(CVE).filter(or_(*conds))
    total = base.count()
    kev_n = base.filter(CVE.kev.is_(True)).count()
    top = (base.order_by(CVE.kev.desc(), CVE.epss_score.desc().nullslast(),
                         CVE.cvss_v3_score.desc().nullslast()).limit(12).all())

    advs = (db.query(DistroAdvisory).filter(func.lower(DistroAdvisory.package) == nl).all())
    fixed = {}
    for a in advs:
        if a.fixed_version:
            fixed.setdefault((a.distro, a.cve_id), a.fixed_version)

    if not total and not advs:
        return (f"I found no CVEs for **{name}** in the local CVE database, and no distro "
                f"advisories for that package. (Import NVD feeds / distro feeds if you expect data.)")

    lines = [f"**{name} — CVE summary (local data)**"]
    if total:
        extra = f" ({kev_n} actively exploited / KEV)" if kev_n else ""
        lines.append(f"**{total}** CVE(s) in the local DB list **{name}** as affected{extra}. Highest-risk:")
        for c in top:
            tag = " [KEV]" if c.kev else ""
            cvss = c.cvss_v3_score if c.cvss_v3_score is not None else c.cvss_v2_score
            lines.append(f"• {c.cve_id} ({c.severity}, CVSS {cvss if cvss is not None else '?'}){tag}")
        if total > len(top):
            lines.append(f"…and {total - len(top)} more — see the CVE Database page (filter by product '{name}').")
    if advs:
        lines.append(f"\nDistro advisories for **{name}**: {len(advs)} (backport-aware fixes). Examples:")
        for (distro, cve_id), fv in list(fixed.items())[:8]:
            lines.append(f"• {distro}: {cve_id} fixed in {fv}")
    return "\n".join(lines)


def _scan_inprogress(scan) -> str:
    """Message for a scan that hasn't finished — don't present partial results as final."""
    if scan.status in ("running", "queued", "pending"):
        pct = f" ({scan.progress}% complete)" if scan.status == "running" else ""
        return (f"**Scan #{scan.id} — {scan.scan_type}** is still **{scan.status}**{pct}. "
                f"I'll have the full results once it finishes — ask me again then "
                f"(or I'll post them automatically if I launched it).")
    return ""


def _scan_summary(db: Session, scan) -> str:
    """A deterministic, human-readable summary of a scan's results (no model involved,
    so aggregate counts are always correct)."""
    pending = _scan_inprogress(scan)
    if pending:
        return pending
    sid = scan.id
    finds = db.query(Finding).filter(Finding.scan_id == sid).all()
    web = db.query(WebFinding).filter(WebFinding.scan_id == sid).all()
    cfgs = [c for c in db.query(ConfigFinding).filter(ConfigFinding.scan_id == sid).all()
            if c.check_id != "audit-summary"]
    lines = [f"**Scan #{sid} — {scan.scan_type}** · status: {scan.status}."]

    if scan.scan_type == "cis_benchmark":
        from .cis_runner import summarize_cis
        m = summarize_cis(db, scan)
        score = f"{m['score']:.0f}%" if m["score"] is not None else "n/a"
        lines.append(f"Host/distro: {m['distro']} · Benchmark: {m['level']} · Engine: {m['engine']} "
                     f"· Compliance score: {score}.")
        lines.append(f"**{m['fails']} failed** of {m['total']} controls checked.")
        fails = [c for c in cfgs if c.status == "fail"]
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        fails.sort(key=lambda c: rank.get(c.severity, 0), reverse=True)
        if fails:
            lines.append("Top failed controls:")
            for c in fails[:8]:
                lines.append(f"• [{c.severity}] {c.title or c.check_id}")
        return "\n".join(lines)

    # Network / credentialed (CVE) + web findings
    if finds:
        sev = {}
        for f in finds:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE", "UNKNOWN"]
        brk = ", ".join(f"{k} {sev[k]}" for k in order if sev.get(k))
        lines.append(f"**{len(finds)} CVE finding(s)** ({brk}).")
        cve_ids = {f.cve_id for f in finds}
        intel = {c.cve_id: c for c in db.query(CVE).filter(CVE.cve_id.in_(cve_ids)).all()} if cve_ids else {}
        kev = [f for f in finds if intel.get(f.cve_id) and intel[f.cve_id].kev]
        if kev:
            lines.append(f"⚠ {len(kev)} are actively exploited (CISA KEV).")
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        finds.sort(key=lambda f: (1 if (intel.get(f.cve_id) and intel[f.cve_id].kev) else 0,
                                  rank.get(f.severity, 0), f.cvss_score or 0), reverse=True)
        lines.append("Top findings:")
        for f in finds[:8]:
            svc = f.service
            pkg = (svc.product or svc.service_name or "") if svc else ""
            tag = " [KEV]" if (intel.get(f.cve_id) and intel[f.cve_id].kev) else ""
            lines.append(f"• {f.cve_id} ({f.severity}) on {pkg or 'asset'}{tag}")
    elif scan.scan_type in ("discovery", "port", "full", "custom", "credentialed"):
        lines.append("No CVE findings were correlated.")

    if web:
        sevw = {}
        for w in web:
            sevw[w.severity] = sevw.get(w.severity, 0) + 1
        brk = ", ".join(f"{k} {v}" for k, v in sevw.items())
        lines.append(f"**{len(web)} web finding(s)** ({brk}).")
        for w in web[:6]:
            lines.append(f"• {w.name} [{w.category}] — {w.severity}")
    return "\n".join(lines)


def _scan_context(db: Session, scan) -> str:
    """A fuller, plain-language fact sheet for one scan — fed to the model so it can answer
    a SPECIFIC question (e.g. 'what are the criticals?', 'remediation for X?'). Bounded."""
    pending = _scan_inprogress(scan)
    if pending:
        return pending
    sid = scan.id
    lines = [f"Scan #{sid} type={scan.scan_type} status={scan.status} target={scan.target.address if scan.target else '?'}"]

    if scan.scan_type == "cis_benchmark":
        from .cis_runner import summarize_cis
        m = summarize_cis(db, scan)
        lines.append(f"distro={m['distro']} level={m['level']} engine={m['engine']} "
                     f"score={m['score']} failed={m['fails']} of {m['total']} controls")
        cfgs = [c for c in db.query(ConfigFinding).filter(ConfigFinding.scan_id == sid).all()
                if c.check_id != "audit-summary"]
        fails = [c for c in cfgs if c.status == "fail"]
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        fails.sort(key=lambda c: rank.get(c.severity, 0), reverse=True)
        lines.append("FAILED CONTROLS:")
        for c in fails[:25]:
            rem = (c.remediation or "").strip().replace("\n", " ")[:160]
            lines.append(f"- [{c.severity}] {c.title or c.check_id}" + (f" — fix: {rem}" if rem else ""))
        return "\n".join(lines)

    finds = db.query(Finding).filter(Finding.scan_id == sid).all()
    if finds:
        cve_ids = {f.cve_id for f in finds}
        cmap = {c.cve_id: c for c in db.query(CVE).filter(CVE.cve_id.in_(cve_ids)).all()} if cve_ids else {}
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        # Severity-first so a "what are the criticals?" question surfaces actual CRITICALs
        # (KEV is a tiebreaker within a severity, and is also flagged inline).
        finds.sort(key=lambda f: (rank.get(f.severity, 0),
                                  1 if (cmap.get(f.cve_id) and cmap[f.cve_id].kev) else 0,
                                  f.cvss_score or 0), reverse=True)
        sev = {}
        for f in finds:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        lines.append(f"TOTAL CVE findings: {len(finds)}")
        lines.append("severity counts: " + ", ".join(f"{k}={v}" for k, v in sev.items()))
        lines.append(f"(showing the top {min(20, len(finds))} of {len(finds)} below)")
        lines.append("FINDINGS (highest risk first):")
        for f in finds[:20]:
            svc = f.service
            pkg = (svc.product or svc.service_name or "") if svc else ""
            c = cmap.get(f.cve_id)
            rem = ((c.remediation if c else "") or "").strip().replace("\n", " ")[:140]
            tag = " KEV" if (c and c.kev) else ""
            lines.append(f"- {f.cve_id} {f.severity} CVSS={f.cvss_score or '?'}{tag} on {pkg or 'asset'}"
                         + (f" — fix: {rem}" if rem else ""))
    else:
        lines.append("No CVE findings correlated.")

    web = db.query(WebFinding).filter(WebFinding.scan_id == sid).all()
    if web:
        lines.append("WEB FINDINGS:")
        for w in web[:15]:
            rem = (w.remediation or "").strip().replace("\n", " ")[:140]
            lines.append(f"- {w.name} [{w.category}] {w.severity}" + (f" — fix: {rem}" if rem else ""))
    return "\n".join(lines)


_SYSTEM = (
    "You are ThreatProbe's offline security assistant for an air-gapped VAPT platform. "
    "Answer ONLY using the facts in the CONTEXT block. Be concise, practical and accurate. "
    "Always cite CVE IDs you reference. If the CONTEXT is empty or doesn't cover the "
    "question, give brief general security guidance and clearly say you have no local "
    "record for it. Never invent CVE IDs, CVSS scores, versions or fixes."
)


def _fallback(message: str, ctx: dict) -> str:
    if ctx["blocks"]:
        return ("The local AI model is offline, so here are the matching facts from the "
                "local database:\n\n" + "\n".join(ctx["blocks"]))
    return ("The local AI model is offline and I found no matching CVE, scan or package "
            "record for that query. Try a CVE ID (e.g. CVE-2023-2975), 'scan #<id>', a "
            "package name, or a vuln class (XSS, SQLi, SSRF, CSP…).")


_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "NONE": 0, "UNKNOWN": 0}
_RANK_NAME = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}


def _resolve_scan(db: Session, message: str):
    """A single scan from '#N', a bare number, or the latest scan for a target IP/host."""
    m = SCAN_RE.search(message)
    if m:
        return db.get(Scan, int(m.group(1)))
    host = _extract_host(message)
    if host:
        t = db.query(Target).filter(func.lower(Target.address).like(f"%{host.lower()}%")).first()
        if t:
            return (db.query(Scan).filter(Scan.target_id == t.id)
                    .order_by(Scan.created_at.desc()).first())
    if not CVE_RE.search(message):
        nm = re.search(r"(?<![\d.\-])(\d{1,6})(?![\d.\-])", message)
        if nm:
            return db.get(Scan, int(nm.group(1)))
    return None


def _answer_fixplan(db: Session, message: str) -> dict:
    """Deterministic, prioritised remediation plan: group findings by package, recommend
    the distro-fixed version, order by KEV → severity → CVE count."""
    scan = _resolve_scan(db, message)
    if scan:
        finds = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        scope = f"scan #{scan.id} ({scan.target.address if scan.target else '?'})"
        cites = [f"scan#{scan.id}"]
    else:
        finds = db.query(Finding).all()
        scope = "all scans"
        cites = []
    if not finds:
        return {"reply": f"No CVE findings to build a patch plan for ({scope}).",
                "citations": cites, "grounded": True, "model": False}
    cve_ids = {f.cve_id for f in finds}
    cmap = {c.cve_id: c for c in db.query(CVE).filter(CVE.cve_id.in_(cve_ids)).all()}
    groups = {}
    for f in finds:
        svc = f.service
        pkg = (svc.product or svc.service_name or "asset") if svc else "asset"
        g = groups.setdefault(pkg, {"cves": set(), "kev": 0, "sev": 0})
        g["cves"].add(f.cve_id)
        c = cmap.get(f.cve_id)
        if c and c.kev:
            g["kev"] += 1
        g["sev"] = max(g["sev"], _RANK.get(f.severity, 0))

    def fixver(pkg, cves):
        best = None
        for a in db.query(DistroAdvisory).filter(func.lower(DistroAdvisory.package) == pkg.lower(),
                                                 DistroAdvisory.cve_id.in_(cves)).all():
            if a.fixed_version and (best is None
                                    or version_compare.compare(a.manager or "rpm", a.fixed_version, best) > 0):
                best = a.fixed_version
        return best

    items = [(pkg, g, fixver(pkg, g["cves"])) for pkg, g in groups.items()]
    items.sort(key=lambda x: (1 if x[1]["kev"] else 0, x[1]["sev"], len(x[1]["cves"])), reverse=True)
    lines = [f"**Patch plan — {scope}**: {len(finds)} finding(s) across {len(groups)} package(s). "
             f"Fix in this order:"]
    for i, (pkg, g, fv) in enumerate(items[:15], 1):
        action = f"upgrade to **{fv}**" if fv else "apply the vendor security update"
        kev = f", {g['kev']} KEV" if g["kev"] else ""
        lines.append(f"{i}. **{pkg}** — {action} → fixes {len(g['cves'])} CVE(s) "
                     f"(max {_RANK_NAME[g['sev']]}{kev})")
    if len(items) > 15:
        lines.append(f"…and {len(items) - 15} more package(s). Ask for the full report or CSV.")
    return {"reply": "\n".join(lines), "citations": cites, "grounded": True, "model": False}


def _scan_domain(scan) -> str:
    """Finding domain — only scans in the SAME domain are comparable."""
    if scan.scan_type == "cis_benchmark":
        return "cis"
    if scan.scan_type in ("web", "zap_passive", "zap_active"):
        return "web"
    return "cve"


def _scan_keys(db: Session, scan) -> dict:
    """Map of finding-key -> label, for diffing two scans of the SAME domain."""
    dom = _scan_domain(scan)
    if dom == "cis":
        rows = db.query(ConfigFinding).filter(ConfigFinding.scan_id == scan.id,
                                              ConfigFinding.status == "fail").all()
        return {c.check_id: f"[{c.severity}] {c.title or c.check_id}" for c in rows}
    if dom == "web":
        out = {}
        for w in db.query(WebFinding).filter(WebFinding.scan_id == scan.id).all():
            out[(w.name, w.target_url or "")] = f"{w.name} [{w.category}] ({w.severity})"
        return out
    out = {}
    for f in db.query(Finding).filter(Finding.scan_id == scan.id).all():
        svc = f.service
        pkg = (svc.product or svc.service_name or "asset") if svc else "asset"
        out[(f.cve_id, pkg)] = f"{f.cve_id} on {pkg} ({f.severity})"
    return out


def _answer_diff(db: Session, message: str):
    """Compare two scans of the SAME type/domain: two explicit ids, or the last two
    same-type scans for a target. Refuses to diff incomparable types (e.g. a CVE/package
    scan vs. a CIS benchmark) — that would mislabel every finding as new/resolved."""
    nums = [int(n) for n in re.findall(r"(?<![\d.\-])(\d{1,6})(?![\d.\-])", message)
            if not CVE_RE.search(message)]
    a = b = None
    if len(nums) >= 2:
        a, b = db.get(Scan, min(nums[0], nums[1])), db.get(Scan, max(nums[0], nums[1]))
    else:
        host = _extract_host(message)
        t = (db.query(Target).filter(func.lower(Target.address).like(f"%{host.lower()}%")).first()
             if host else None)
        if not t and len(nums) == 1:
            s1 = db.get(Scan, nums[0])
            t = s1.target if s1 else None
        if t:
            recent = (db.query(Scan).filter(Scan.target_id == t.id, Scan.status == "completed")
                      .order_by(Scan.created_at.desc()).limit(15).all())
            if recent:
                newest = recent[0]
                prev = next((s for s in recent[1:] if _scan_domain(s) == _scan_domain(newest)), None)
                if prev:
                    b, a = newest, prev  # newest=b, previous same-type=a
                else:
                    return {"reply": f"There's only one completed **{newest.scan_type}** scan on "
                                     f"{t.address} (#{newest.id}), so there's nothing of the same "
                                     f"type to compare it against yet.", "citations": [f"scan#{newest.id}"],
                            "grounded": True, "model": False}
    if not a or not b:
        return None
    if a.target_id != b.target_id:
        return {"reply": f"Scan #{a.id} is on **{a.target.address if a.target else '?'}** and "
                         f"#{b.id} is on **{b.target.address if b.target else '?'}** — comparing "
                         f"scans of different targets isn't meaningful. Pick two scans of the "
                         f"same target.", "citations": [f"scan#{a.id}", f"scan#{b.id}"],
                "grounded": True, "model": False}
    if _scan_domain(a) != _scan_domain(b):
        return {"reply": f"Scan #{a.id} is a **{a.scan_type}** scan and #{b.id} is a "
                         f"**{b.scan_type}** scan — different scan types can't be meaningfully "
                         f"compared (their findings aren't the same kind). Pick two scans of the "
                         f"same type.", "citations": [f"scan#{a.id}", f"scan#{b.id}"],
                "grounded": True, "model": False}
    ak, bk = _scan_keys(db, a), _scan_keys(db, b)
    new = [bk[k] for k in bk if k not in ak]
    fixed = [ak[k] for k in ak if k not in bk]
    common = [k for k in bk if k in ak]
    lines = [f"**Compared scan #{a.id} → #{b.id}** ({(b.target.address if b.target else '?')}): "
             f"**{len(new)} new**, **{len(fixed)} resolved**, {len(common)} unchanged."]
    if new:
        lines.append(f"\n🆕 New ({len(new)}):")
        lines += [f"• {x}" for x in new[:10]]
        if len(new) > 10:
            lines.append(f"…and {len(new) - 10} more.")
    if fixed:
        lines.append(f"\n✅ Resolved ({len(fixed)}):")
        lines += [f"• {x}" for x in fixed[:10]]
        if len(fixed) > 10:
            lines.append(f"…and {len(fixed) - 10} more.")
    return {"reply": "\n".join(lines), "citations": [f"scan#{a.id}", f"scan#{b.id}"],
            "grounded": True, "model": False}


def answer(db: Session, message: str, history: list | None = None) -> dict:
    """Return {'reply': str, 'citations': [...], 'grounded': bool, 'model': bool}."""
    # Deterministic, cross-scan capabilities first (model-free — always accurate).
    if FIXPLAN_RE.search(message):
        return _answer_fixplan(db, message)
    if DIFF_RE.search(message):
        diff = _answer_diff(db, message)
        if diff:
            return diff
    ctx = retrieve(db, message)
    # Package CVE lookups are deterministic (accurate counts + KEV + distro fixes).
    if ctx.get("pkg_summary"):
        return {"reply": ctx["pkg_summary"], "citations": ctx["citations"],
                "grounded": True, "model": False}
    # Scan queries: a plain "summarise scan N" returns the DETERMINISTIC summary (a small
    # model misreads aggregate counts — e.g. inverting "6 failed" into "no failures"). But
    # a SPECIFIC question ("what are the criticals?", "remediation for X?") is answered by
    # the model from the scan's fact sheet, so the user gets a focused insight, not a dump.
    if ctx.get("scan_summary"):
        specific = (bool(SPECIFIC_RE.search(message)) and not COUNT_RE.search(message)
                    and ctx.get("scan_context"))
        if not specific or not llm_available():
            return {"reply": ctx["scan_summary"], "citations": ctx["citations"],
                    "grounded": True, "model": False}
        messages = [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": f"SCAN FACTS:\n{ctx['scan_context'][:4000]}\n\n"
                                        f"Answer this question about the scan using ONLY the "
                                        f"facts above, concisely: {message}"},
        ]
        try:
            reply = _chat_llm(messages) or ctx["scan_summary"]
        except Exception:
            reply = ctx["scan_summary"]
        return {"reply": reply, "citations": ctx["citations"], "grounded": True, "model": True}
    context_text = "\n".join(ctx["blocks"]) if ctx["blocks"] else "(no matching local records)"
    if not llm_available():
        return {"reply": _fallback(message, ctx), "citations": ctx["citations"],
                "grounded": bool(ctx["blocks"]), "model": False}
    messages = [{"role": "system", "content": _SYSTEM}]
    for turn in (history or [])[-4:]:
        role = "assistant" if turn.get("role") == "assistant" else "user"
        messages.append({"role": role, "content": str(turn.get("content", ""))[:1500]})
    messages.append({"role": "user",
                     "content": f"CONTEXT:\n{context_text[:4000]}\n\nQUESTION: {message}"})
    try:
        reply = _chat_llm(messages) or _fallback(message, ctx)
    except Exception:
        reply = _fallback(message, ctx)
    return {"reply": reply, "citations": ctx["citations"],
            "grounded": bool(ctx["blocks"]), "model": True}
