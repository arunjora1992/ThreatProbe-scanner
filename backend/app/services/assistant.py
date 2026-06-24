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

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..models import (CVE, ConfigFinding, DistroAdvisory, Finding, Host, Package,
                      Scan, Service, WebFinding)

CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
SCAN_RE = re.compile(r"scan\s*#?\s*(\d+)", re.I)
PKG_RE = re.compile(r"(?:package|is|about)\s+([a-zA-Z0-9][\w.+-]{1,40})", re.I)
HOST_RE = re.compile(r"https?://([^/\s]+)|\b(\d{1,3}(?:\.\d{1,3}){3})\b|\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)
# Stems (no trailing \b) so "summarise", "vulnerability", "findings", "scanning" all match.
SCAN_INTENT_RE = re.compile(
    r"\b(scan|result|audit|finding|vulnerab|compliance|report|assessment|summar|show)\w*", re.I)


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
        citations.append(f"scan#{scan.id}")
        scan_summary = _scan_summary(db, scan)
        blocks.append(f"[SCAN]{note} " + scan_summary.replace("\n", " "))

    # ---- package name ----
    if not citations:  # only if nothing more specific matched
        pm = PKG_RE.search(message)
        if pm:
            name = pm.group(1).lower()
            if name not in ("the", "this", "it", "there", "vulnerable", "any"):
                advs = (db.query(DistroAdvisory)
                        .filter(func.lower(DistroAdvisory.package) == name)
                        .limit(8).all())
                if advs:
                    citations.append(name)
                    blocks.append(f"[PACKAGE] '{name}' — {len(advs)} distro advisory match(es) (sample):")
                    for a in advs:
                        blocks.append(f"  - {a.distro} {a.release}: {a.cve_id} fixed in {a.fixed_version or 'n/a'}")

    # ---- vuln-class education ----
    low = message.lower()
    seen = set()
    for kw, (title, what, fix) in VULN_CLASS_DOCS.items():
        if kw in low and title not in seen:
            seen.add(title)
            blocks.append(f"[CLASS] {title}: {what} Fix: {fix}")

    return {"blocks": blocks, "citations": list(dict.fromkeys(citations)),
            "scan_summary": scan_summary}


def _scan_summary(db: Session, scan) -> str:
    """A deterministic, human-readable summary of a scan's results (no model involved,
    so aggregate counts are always correct)."""
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


def answer(db: Session, message: str, history: list | None = None) -> dict:
    """Return {'reply': str, 'citations': [...], 'grounded': bool, 'model': bool}."""
    ctx = retrieve(db, message)
    # Scan summaries are returned deterministically — a small model misreads aggregate
    # counts (e.g. inverting "6 failed" into "no failures"), which is unacceptable here.
    if ctx.get("scan_summary"):
        return {"reply": ctx["scan_summary"], "citations": ctx["citations"],
                "grounded": True, "model": False}
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
