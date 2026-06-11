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
    zap_active_max_minutes: int = 20


settings = Settings()
