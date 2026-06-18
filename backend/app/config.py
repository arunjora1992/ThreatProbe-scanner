"""Application configuration loaded from environment variables.

All settings have sensible defaults so the stack runs out-of-the-box in an
air-gapped environment with no external dependencies.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql+psycopg2://pentest:pentest@db:5432/pentest"

    # Auth
    secret_key: str = "change-me-in-production-please-use-a-long-random-string"
    access_token_expire_minutes: int = 480
    algorithm: str = "HS256"

    # Bootstrap admin (created on first start if no users exist)
    admin_username: str = "admin"
    admin_password: str = "admin123"

    # Scanning
    # Directory inside the container where NVD JSON feeds are mounted for offline import.
    cve_feed_dir: str = "/data/cve_feeds"
    # nmap default flags. -sT (TCP connect) works without root; switch to -sS when privileged.
    nmap_default_flags: str = "-sT -sV -T4 --open"
    # Hard cap on scan runtime (seconds) to avoid runaway jobs.
    scan_timeout_seconds: int = 3600
    # How often the worker polls the DB for queued scans (seconds).
    worker_poll_interval: int = 5

    # CORS (frontend origin). "*" is fine for an internal air-gapped deployment.
    cors_origins: str = "*"

    # OWASP ZAP daemon (web-application scanning engine)
    zap_api_url: str = "http://zap:8090"
    zap_api_key: str = ""  # empty == API key disabled (internal/air-gapped use)
    zap_spider_max_minutes: int = 5
    zap_active_max_minutes: int = 15
    # Scope bounds — keep the crawl/scan finite so memory stays bounded on real sites.
    zap_spider_max_depth: int = 5
    zap_spider_max_children: int = 12
    # AJAX (browser-driven) spider — needed to crawl JavaScript/SPA apps whose routes
    # and API calls the traditional spider can't see. Launches a headless browser, so
    # it is heavier; keep it bounded. Enabled per-scan from the UI.
    zap_ajax_max_minutes: int = 5
    zap_ajax_max_crawl_depth: int = 10
    zap_ajax_browser: str = "firefox-headless"
    # ZAP defaults the AJAX spider to one browser PER CPU CORE (e.g. 16), which blows
    # the container's memory and crashes ZAP when those browsers are torn down. Pin it
    # low so memory stays bounded. Bump only if the ZAP container has lots of RAM.
    zap_ajax_browsers: int = 1
    zap_ajax_max_crawl_states: int = 50   # 0 = unlimited; bound it so big sites stay finite


settings = Settings()
