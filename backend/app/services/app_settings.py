"""GUI-tunable, tool-level application settings.

A small registry (DEFINITIONS) declares every setting with its group, type, default,
label and help text. Overrides are stored one-row-per-key in the app_settings table and
merged over the defaults at read time. The engine (scanner, ZAP, auth, scheduler) reads
these at runtime via get()/get_int()/get_bool(), so operators can tune the platform from
the Settings page with no .env edit or rebuild.

Reads are served from a short-TTL process cache so hot paths don't hit the DB every call;
writes invalidate it. The worker and backend are separate processes — each keeps its own
cache and re-reads within TTL seconds, which is fine for these low-churn knobs.
"""
import threading
import time
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ..config import settings as _env
from ..database import SessionLocal
from ..models import AppSetting

# group key -> display name (also defines tab order in the GUI)
GROUPS = [
    ("scanning", "Scanning"),
    ("zap", "Web / ZAP"),
    ("matching", "Matching & data"),
    ("security", "Security & scope"),
    ("assistant", "AI Assistant"),
]

# key -> definition. type in {str, text, int, bool, choice}.
DEFINITIONS: Dict[str, dict] = {
    # ---- Scanning ----
    "scan_nmap_flags": {
        "group": "scanning", "type": "str", "default": _env.nmap_default_flags,
        "label": "Default nmap flags",
        "help": "Flags used for the Server VA (full) profile."},
    "scan_use_syn": {
        "group": "scanning", "type": "bool", "default": False,
        "label": "Use privileged SYN scan (-sS)",
        "help": "Faster half-open scan; needs NET_RAW (the worker has it). Rewrites -sT to -sS."},
    "scan_timeout_seconds": {
        "group": "scanning", "type": "int", "default": _env.scan_timeout_seconds,
        "label": "Scan timeout (seconds)", "min": 60, "max": 86400,
        "help": "Hard cap on a single scan's runtime."},
    "scan_default_profile": {
        "group": "scanning", "type": "choice", "default": "full",
        "choices": ["full", "discovery", "port", "web", "zap_passive", "zap_active",
                    "credentialed", "cis_benchmark"],
        "label": "Default scan type", "help": "Pre-selected scan type in the launch dialog."},
    "cis_oscap_timeout_seconds": {
        "group": "scanning", "type": "int", "default": 3600, "min": 300, "max": 14400,
        "label": "CIS OpenSCAP eval timeout (seconds)",
        "help": "Max time for the OpenSCAP CIS evaluation over SSH. Filesystem-walking rules "
                "(e.g. world-writable checks) are slow on large disks, so the default is 1 "
                "hour (3600s). On timeout the scan falls back to the built-in hardening "
                "checks instead of failing. Raise up to 4 hours for very large VMs."},

    # ---- Web / ZAP ----
    "zap_spider_max_minutes": {
        "group": "zap", "type": "int", "default": _env.zap_spider_max_minutes,
        "label": "Spider max (minutes)", "min": 1, "max": 120},
    "zap_active_max_minutes": {
        "group": "zap", "type": "int", "default": _env.zap_active_max_minutes,
        "label": "Active scan max (minutes)", "min": 1, "max": 480},
    "zap_spider_max_depth": {
        "group": "zap", "type": "int", "default": _env.zap_spider_max_depth,
        "label": "Spider max depth", "min": 1, "max": 20},
    "zap_spider_max_children": {
        "group": "zap", "type": "int", "default": _env.zap_spider_max_children,
        "label": "Spider max children / node", "min": 0, "max": 200,
        "help": "0 = unlimited."},
    "zap_ajax_max_minutes": {
        "group": "zap", "type": "int", "default": _env.zap_ajax_max_minutes,
        "label": "AJAX spider max (minutes)", "min": 0, "max": 120},
    "zap_ajax_browsers": {
        "group": "zap", "type": "int", "default": _env.zap_ajax_browsers,
        "label": "AJAX browsers", "min": 1, "max": 8,
        "help": "Headless browsers for the AJAX spider. Higher = more memory."},
    "zap_ajax_max_crawl_states": {
        "group": "zap", "type": "int", "default": _env.zap_ajax_max_crawl_states,
        "label": "AJAX max crawl states", "min": 0, "max": 2000, "help": "0 = unlimited."},

    # ---- Matching & data ----
    "match_min_severity": {
        "group": "matching", "type": "choice", "default": "INFO",
        "choices": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "label": "Minimum severity shown",
        "help": "Hide findings below this severity in the GUI and reports. Data is still stored."},
    "match_default_sort": {
        "group": "matching", "type": "choice", "default": "risk",
        "choices": ["risk", "cvss", "epss"],
        "label": "Default CVE sort",
        "help": "Default ordering on the CVE Database page. risk = KEV → EPSS → CVSS."},
    "data_scan_retention_days": {
        "group": "matching", "type": "int", "default": 0, "min": 0, "max": 3650,
        "label": "Auto-delete scans older than (days)",
        "help": "0 = keep forever. A daily cleanup removes older scans and their findings."},
    "data_log_max_chars": {
        "group": "matching", "type": "int", "default": 200000, "min": 10000, "max": 5000000,
        "label": "Live-log cap (characters)",
        "help": "Truncate a scan's live log beyond this size."},

    # ---- Security & scope ----
    "security_session_minutes": {
        "group": "security", "type": "int", "default": _env.access_token_expire_minutes,
        "label": "Session lifetime (minutes)", "min": 5, "max": 10080,
        "help": "How long a login token stays valid."},
    "security_password_min_length": {
        "group": "security", "type": "int", "default": 8, "min": 4, "max": 128,
        "label": "Password minimum length", "help": "Enforced when creating users."},
    "security_scope_allowlist": {
        "group": "security", "type": "text", "default": "",
        "label": "Target scope allowlist",
        "help": "One per line or comma-separated: CIDR (10.0.0.0/8) or host/URL glob "
                "(*.lab.local). Empty = no restriction. Scans whose target falls outside "
                "the list are blocked."},

    # ---- AI assistant ----
    "assistant_enabled": {
        "group": "assistant", "type": "bool", "default": True,
        "label": "Enable the offline AI assistant",
        "help": "Show the chat widget. The assistant answers from local data only "
                "(grounded on the CVE DB / scan findings) using the bundled offline model."},
    "assistant_agent_mode": {
        "group": "assistant", "type": "bool", "default": False,
        "label": "Agentic mode (multi-step tool-calling)",
        "help": "Let the model plan multi-step and call read-only data tools (ReAct) instead "
                "of rule-based routing. Needs a tool-capable model — use a 7B (e.g. "
                "Qwen2.5-7B-Instruct) via the model manager; small models do this unreliably. "
                "Falls back to the standard assistant on error."},
    "llm_mode": {
        "group": "assistant", "type": "choice", "default": "local", "choices": ["local", "remote"],
        "label": "AI model source",
        "help": "local = the bundled offline model in this deployment. remote = an "
                "OpenAI-compatible server elsewhere (e.g. a GPU box running llama.cpp or "
                "Ollama). Switch any time — the rest of the assistant is unchanged."},
    "llm_remote_url": {
        "group": "assistant", "type": "str", "default": "",
        "label": "Remote model URL (when source = remote)",
        "help": "Base URL of an OpenAI-compatible server, e.g. http://192.168.1.50:8091 . "
                "The assistant calls <url>/v1/chat/completions."},
    "llm_remote_model": {
        "group": "assistant", "type": "str", "default": "",
        "label": "Remote model name",
        "help": "Model id to request from the remote server (e.g. qwen2.5-7b-instruct). "
                "Leave blank for servers that ignore it."},
    "llm_remote_api_key": {
        "group": "assistant", "type": "str", "default": "",
        "label": "Remote API key (optional)",
        "help": "Bearer token if the remote server requires auth. Stored in the database."},
}

_TTL = 5.0
_lock = threading.Lock()
_cache: Dict[str, str] = {}
_cache_ts = 0.0


def _refresh_locked() -> None:
    global _cache, _cache_ts
    db = SessionLocal()
    try:
        _cache = {r.key: r.value for r in db.query(AppSetting).all()}
        _cache_ts = time.monotonic()
    finally:
        db.close()


def _raw(key: str) -> Optional[str]:
    if not _cache_ts or (time.monotonic() - _cache_ts) > _TTL:
        with _lock:
            if not _cache_ts or (time.monotonic() - _cache_ts) > _TTL:
                _refresh_locked()
    return _cache.get(key)


def invalidate() -> None:
    global _cache_ts
    _cache_ts = 0.0


def _cast(typ: str, raw: str, default: Any) -> Any:
    try:
        if typ == "int":
            return int(str(raw).strip())
        if typ == "bool":
            return str(raw).strip().lower() in ("1", "true", "yes", "on")
        return str(raw)
    except (ValueError, TypeError):
        return default


def get(key: str) -> Any:
    """Typed value for a setting (DB override or built-in default)."""
    d = DEFINITIONS[key]
    raw = _raw(key)
    if raw is None or raw == "":
        return d["default"]
    return _cast(d["type"], raw, d["default"])


def get_int(key: str) -> int:
    return int(get(key))


def get_bool(key: str) -> bool:
    return bool(get(key))


def get_str(key: str) -> str:
    return str(get(key))


def _validate(d: dict, val: Any) -> str:
    """Coerce + clamp an incoming value to the stored string form."""
    typ = d["type"]
    if typ == "bool":
        b = val if isinstance(val, bool) else str(val).strip().lower() in ("1", "true", "yes", "on")
        return "true" if b else "false"
    if typ == "int":
        n = int(val)
        if "min" in d:
            n = max(d["min"], n)
        if "max" in d:
            n = min(d["max"], n)
        return str(n)
    if typ == "choice":
        s = str(val)
        return s if s in d.get("choices", []) else str(d["default"])
    return str(val)


def all_grouped() -> List[dict]:
    """Registry + current values, grouped for the Settings GUI."""
    out = []
    for gkey, gname in GROUPS:
        items = []
        for key, d in DEFINITIONS.items():
            if d["group"] != gkey:
                continue
            items.append({
                "key": key, "label": d["label"], "help": d.get("help", ""),
                "type": d["type"], "choices": d.get("choices"),
                "min": d.get("min"), "max": d.get("max"),
                "value": get(key), "default": d["default"],
            })
        out.append({"group": gkey, "name": gname, "items": items})
    return out


def set_many(db: Session, values: Dict[str, Any]) -> None:
    for key, val in values.items():
        d = DEFINITIONS.get(key)
        if not d:
            continue
        sval = _validate(d, val)
        row = db.get(AppSetting, key)
        if row is None:
            db.add(AppSetting(key=key, value=sval))
        else:
            row.value = sval
            row.updated_at = _now()
    db.commit()
    invalidate()


def reset_group(db: Session, group: str) -> int:
    keys = [k for k, d in DEFINITIONS.items() if d["group"] == group]
    if not keys:
        return 0
    n = db.query(AppSetting).filter(AppSetting.key.in_(keys)).delete(synchronize_session=False)
    db.commit()
    invalidate()
    return n


def _now():
    from datetime import datetime
    return datetime.utcnow()
