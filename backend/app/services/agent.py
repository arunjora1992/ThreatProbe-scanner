"""ReAct tool-calling agent loop for the offline assistant (opt-in 'agentic mode').

The model is given READ-ONLY, DB-grounded tools and plans multi-step: it decides which
tools to call, we execute them (deterministic Python returning JSON/text), feed the
results back, and loop until it answers. Facts come from the tools (accurate); the model
does the reasoning and phrasing. This needs a tool-capable model (Qwen2.5-7B-Instruct is
ideal; small models tool-call unreliably) and the llama.cpp server started with --jinja.

Write-actions (launch/stop/schedule scans) are deliberately NOT exposed to the autonomous
loop — those stay in the confirmed, rule-based chat path. The caller falls back to
assistant.answer() on any failure.
"""
import json

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..config import settings
from ..models import CVE, ConfigFinding, Finding, Host, Scan, Target, WebFinding
from . import assistant

MAX_STEPS = 6

_SYSTEM = (
    "You are ThreatProbe's security-analyst agent for an air-gapped VAPT platform. "
    "Use the provided tools to fetch facts from the local database — NEVER invent CVE IDs, "
    "counts, versions, or remediations. Plan step by step: call tools as needed, then give a "
    "concise, well-structured answer. Cite CVE IDs and scan numbers (e.g. 'scan #12'). If a "
    "tool returns no data, say so plainly. Do not call write/scan-control actions."
)

# OpenAI-style tool schemas exposed to the model.
TOOLS = [
    {"type": "function", "function": {
        "name": "lookup_cve", "description": "Explain one CVE from the local CVE database.",
        "parameters": {"type": "object", "properties": {
            "cve_id": {"type": "string", "description": "e.g. CVE-2023-2975"}}, "required": ["cve_id"]}}},
    {"type": "function", "function": {
        "name": "search_cves", "description": "Search the local CVE database by affected product and/or severity.",
        "parameters": {"type": "object", "properties": {
            "product": {"type": "string"},
            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            "kev_only": {"type": "boolean"},
            "limit": {"type": "integer"}}}}},
    {"type": "function", "function": {
        "name": "package_cves", "description": "Summarise known CVEs + distro fixes for a package (e.g. kernel, openssl).",
        "parameters": {"type": "object", "properties": {
            "package": {"type": "string"}}, "required": ["package"]}}},
    {"type": "function", "function": {
        "name": "list_scans", "description": "List recent scans (id, type, status, target, result count).",
        "parameters": {"type": "object", "properties": {
            "status": {"type": "string"}, "limit": {"type": "integer"}}}}},
    {"type": "function", "function": {
        "name": "scan_summary", "description": "Deterministic result summary for one scan by id.",
        "parameters": {"type": "object", "properties": {
            "scan_id": {"type": "integer"}}, "required": ["scan_id"]}}},
    {"type": "function", "function": {
        "name": "patch_plan", "description": "Prioritised remediation plan for a scan (or all scans if scan_id omitted).",
        "parameters": {"type": "object", "properties": {
            "scan_id": {"type": "integer"}}}}},
    {"type": "function", "function": {
        "name": "diff_scans", "description": "Compare two same-type scans on the same target (new vs resolved findings).",
        "parameters": {"type": "object", "properties": {
            "scan_a": {"type": "integer"}, "scan_b": {"type": "integer"}},
            "required": ["scan_a", "scan_b"]}}},
    {"type": "function", "function": {
        "name": "risk_posture", "description": "Overall environment risk: totals, severity breakdown, KEV, most-at-risk hosts.",
        "parameters": {"type": "object", "properties": {}}}},
]


def _tool_lookup_cve(db, args):
    cid = str(args.get("cve_id", "")).upper()
    c = db.query(CVE).filter(func.upper(CVE.cve_id) == cid).first()
    if not c:
        return f"{cid}: not present in the local CVE database.", []
    return assistant._cve_block(c), [c.cve_id]


def _tool_search_cves(db, args):
    q = db.query(CVE)
    if args.get("product"):
        q = q.filter(func.lower(CVE.cpe_products).like(f"%{str(args['product']).lower()}%"))
    if args.get("severity"):
        q = q.filter(CVE.severity == str(args["severity"]).upper())
    if args.get("kev_only"):
        q = q.filter(CVE.kev.is_(True))
    total = q.count()
    limit = min(int(args.get("limit", 12) or 12), 25)
    rows = q.order_by(CVE.kev.desc(), CVE.epss_score.desc().nullslast(),
                      CVE.cvss_v3_score.desc().nullslast()).limit(limit).all()
    if not total:
        return "No matching CVEs in the local database.", []
    lines = [f"{total} match(es). Top {len(rows)}:"]
    for c in rows:
        lines.append(f"- {c.cve_id} {c.severity} CVSS={c.cvss_v3_score if c.cvss_v3_score is not None else '?'}"
                     + (" KEV" if c.kev else ""))
    return "\n".join(lines), [c.cve_id for c in rows]


def _tool_package_cves(db, args):
    name = str(args.get("package", "")).strip()
    if not name:
        return "No package given.", []
    return assistant._package_summary(db, name), [name]


def _tool_list_scans(db, args):
    q = db.query(Scan)
    if args.get("status"):
        q = q.filter(Scan.status == str(args["status"]))
    rows = q.order_by(Scan.created_at.desc()).limit(min(int(args.get("limit", 10) or 10), 25)).all()
    if not rows:
        return "No scans found.", []
    from ..routers.scans import _result_counts
    counts = _result_counts(db, [s.id for s in rows])
    lines = []
    for s in rows:
        tgt = s.target.address if s.target else "?"
        lines.append(f"#{s.id} {s.scan_type} {s.status} on {tgt} — {counts.get(s.id, 0)} result(s)")
    return "\n".join(lines), []


def _tool_scan_summary(db, args):
    s = db.get(Scan, int(args.get("scan_id", 0)))
    if not s:
        return f"Scan #{args.get('scan_id')} not found.", []
    return assistant._scan_summary(db, s), [f"scan#{s.id}"]


def _tool_patch_plan(db, args):
    sid = args.get("scan_id")
    res = assistant._answer_fixplan(db, f"scan #{int(sid)}" if sid else "all scans")
    return res["reply"], res.get("citations", [])


def _tool_diff_scans(db, args):
    a, b = args.get("scan_a"), args.get("scan_b")
    res = assistant._answer_diff(db, f"compare scan {int(a)} and {int(b)}")
    if not res:
        return "Couldn't resolve those two scans.", []
    return res["reply"], res.get("citations", [])


def _tool_risk_posture(db, args):
    sev = dict(db.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all())
    kev = (db.query(Finding).join(CVE, CVE.cve_id == Finding.cve_id).filter(CVE.kev.is_(True)).count())
    crit_high_open = (db.query(Finding).filter(Finding.severity.in_(["CRITICAL", "HIGH"]),
                                               Finding.status == "open").count())
    cis_fail = db.query(ConfigFinding).filter(ConfigFinding.status == "fail").count()
    web = db.query(WebFinding).count()
    # Most-at-risk hosts by critical/high finding count.
    host_rows = (db.query(Host.address, func.count(Finding.id))
                 .join(Finding, Finding.scan_id == Host.scan_id)
                 .filter(Finding.severity.in_(["CRITICAL", "HIGH"]))
                 .group_by(Host.address).order_by(func.count(Finding.id).desc()).limit(5).all())
    lines = [
        f"Findings by severity: " + (", ".join(f"{k} {v}" for k, v in sev.items()) or "none"),
        f"Actively exploited (KEV) findings: {kev}",
        f"Open CRITICAL/HIGH: {crit_high_open}",
        f"Failed CIS controls: {cis_fail}; Web findings: {web}",
    ]
    if host_rows:
        lines.append("Most-at-risk hosts: " + "; ".join(f"{a} ({n} crit/high)" for a, n in host_rows))
    return "\n".join(lines), []


_DISPATCH = {
    "lookup_cve": _tool_lookup_cve, "search_cves": _tool_search_cves,
    "package_cves": _tool_package_cves, "list_scans": _tool_list_scans,
    "scan_summary": _tool_scan_summary, "patch_plan": _tool_patch_plan,
    "diff_scans": _tool_diff_scans, "risk_posture": _tool_risk_posture,
}


def _chat(messages):
    return assistant._http_json(
        f"{settings.llm_api_url}/v1/chat/completions",
        {"model": settings.llm_model, "messages": messages, "tools": TOOLS,
         "temperature": 0.2, "max_tokens": 800, "stream": False},
        timeout=settings.llm_timeout_seconds,
    )


def agent_answer(db: Session, message: str, history=None) -> dict:
    """Run the ReAct loop. Raises on transport errors so the caller can fall back."""
    messages = [{"role": "system", "content": _SYSTEM}]
    for turn in (history or [])[-4:]:
        role = "assistant" if turn.get("role") == "assistant" else "user"
        messages.append({"role": role, "content": str(turn.get("content", ""))[:1200]})
    messages.append({"role": "user", "content": message})

    citations, used_tools = set(), []
    for _step in range(MAX_STEPS):
        resp = _chat(messages)
        msg = (resp.get("choices") or [{}])[0].get("message", {}) or {}
        tcs = msg.get("tool_calls") or []
        if tcs:
            messages.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": tcs})
            for tc in tcs:
                fn = tc.get("function", {}) or {}
                name = fn.get("name", "")
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except (ValueError, TypeError):
                    args = {}
                handler = _DISPATCH.get(name)
                if handler:
                    used_tools.append(name)
                    try:
                        content, cites = handler(db, args)
                    except Exception as exc:  # noqa: BLE001
                        content, cites = f"tool error: {exc}", []
                    citations.update(cites)
                else:
                    content = f"unknown tool '{name}'"
                messages.append({"role": "tool", "tool_call_id": tc.get("id", name),
                                 "name": name, "content": str(content)[:4000]})
            continue
        reply = (msg.get("content") or "").strip()
        if reply:
            return {"reply": reply, "citations": sorted(citations), "grounded": bool(used_tools),
                    "model": True, "agent": True, "tools_used": used_tools}
        break
    # No final text (e.g. small model looping) — surface whatever facts were gathered.
    return {"reply": "I gathered the data but couldn't compose a final answer with this model "
                     "— try a larger model (Settings → AI model) or rephrase.",
            "citations": sorted(citations), "grounded": bool(used_tools), "model": True,
            "agent": True, "tools_used": used_tools}
