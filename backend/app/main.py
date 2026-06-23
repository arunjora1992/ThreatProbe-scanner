"""FastAPI application entrypoint for the Air-Gapped Pentest Platform."""
import time

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from .config import settings
from .database import Base, engine
from .routers import auth, branding, cves, dashboard, findings, reports, scans, settings as settings_router, targets
from .seed import run_seed

app = FastAPI(
    title="ThreatProbe Scanner",
    description="Network/server vulnerability assessment, URL penetration testing, "
                "local CVE database, and CSV/PDF reporting — built for offline use.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _wait_for_db(retries: int = 30, delay: float = 2.0):
    for attempt in range(1, retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except OperationalError:
            print(f"[api] waiting for database ({attempt}/{retries})...", flush=True)
            time.sleep(delay)
    raise RuntimeError("Database did not become ready in time")


def _ensure_indexes():
    """Best-effort trigram GIN indexes so ILIKE-based CVE correlation stays fast
    even with hundreds of thousands of CVEs. Safe to run repeatedly."""
    stmts = [
        "CREATE EXTENSION IF NOT EXISTS pg_trgm",
        "CREATE INDEX IF NOT EXISTS ix_cve_desc_trgm ON cves USING gin (description gin_trgm_ops)",
        "CREATE INDEX IF NOT EXISTS ix_cve_cpe_trgm ON cves USING gin (cpe_products gin_trgm_ops)",
    ]
    try:
        with engine.begin() as conn:
            for s in stmts:
                conn.execute(text(s))
        print("[api] trigram indexes ensured", flush=True)
    except Exception as exc:  # noqa: BLE001 - index optimisation is non-fatal
        print(f"[api] index setup skipped: {exc}", flush=True)


def _ensure_columns():
    """Add columns introduced after the initial schema (create_all won't alter
    existing tables). Safe to run repeatedly."""
    stmts = [
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS log TEXT DEFAULT ''",
    ]
    try:
        with engine.begin() as conn:
            for s in stmts:
                conn.execute(text(s))
    except Exception as exc:  # noqa: BLE001
        print(f"[api] column migration skipped: {exc}", flush=True)


@app.on_event("startup")
def startup():
    _wait_for_db()
    Base.metadata.create_all(bind=engine)
    _ensure_columns()
    _ensure_indexes()
    run_seed()
    from .services import cve_updater
    cve_updater.start_scheduler()
    print("[api] startup complete", flush=True)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "pentest-platform", "version": "1.0.0"}


app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(cves.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(dashboard.router)
app.include_router(settings_router.router)
app.include_router(branding.router)
