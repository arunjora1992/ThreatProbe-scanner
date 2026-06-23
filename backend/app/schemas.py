"""Pydantic request/response schemas."""
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


# ---- Auth ----
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: str
    is_active: bool


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "operator"


# ---- Targets ----
class TargetCreate(BaseModel):
    name: str
    address: str
    description: str = ""
    tags: str = ""


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    address: str
    description: str
    tags: str
    created_at: datetime


# ---- Scans ----
class ScanCreate(BaseModel):
    target_id: int
    scan_type: str = "full"  # discovery | full | port | web | custom | credentialed
    custom_flags: Optional[str] = None  # only honoured for scan_type == custom
    # Credentials for scan_type == "credentialed" (Linux/SSH). NEVER persisted —
    # used in-memory by the backend for the duration of the scan only.
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_key: Optional[str] = None
    ssh_key_passphrase: Optional[str] = None
    ssh_port: int = 22
    # CIS benchmark (cis_benchmark): which profile/level to evaluate. A suffix matched
    # against the datastream's profile ids (e.g. "_cis_server_l1", "_cis" for L2 server).
    cis_profile: Optional[str] = None
    # Web-app login for authenticated ZAP scans (scan_type == zap_passive/zap_active).
    # Supplying these runs a deeper, logged-in crawl/attack. NEVER persisted —
    # used in-memory by the backend for the duration of the scan only.
    zap_username: Optional[str] = None
    zap_password: Optional[str] = None
    zap_login_url: Optional[str] = None
    zap_auth_type: str = "form"               # form | json | http
    zap_username_field: str = "username"
    zap_password_field: str = "password"
    zap_extra_post_data: Optional[str] = None
    zap_logged_in_regex: Optional[str] = None
    zap_logged_out_regex: Optional[str] = None
    # Session management for token/bearer SPAs and the browser-driven AJAX spider.
    zap_session: str = "cookie"               # cookie | header
    zap_token_field: Optional[str] = None     # JSON field in the login response holding the token
    zap_session_headers: Optional[str] = None  # advanced: full header template override
    zap_ajax_spider: bool = False             # browser-driven crawl for JS/SPA apps


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    target_id: int
    scan_type: str
    profile: str
    status: str
    progress: int
    error: str
    created_by: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]


class ServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    port: int
    protocol: str
    state: str
    service_name: str
    product: str
    version: str
    cpe: str
    banner: str


class HostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    address: str
    hostname: str
    state: str
    os_guess: str
    services: List[ServiceOut] = []


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    service_id: int
    cve_id: str
    severity: str
    cvss_score: Optional[float]
    match_confidence: str
    match_reason: str
    status: str
    notes: str
    created_at: datetime
    # Affected package (credentialed scans) or service/product (network scans).
    package: str = ""
    # Threat-intel enrichment (from the linked CVE) for prioritization.
    kev: bool = False
    epss_score: Optional[float] = None


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None


class ScanDetail(ScanOut):
    hosts: List[HostOut] = []
    finding_count: int = 0


# ---- CVEs ----
class CVEOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cve_id: str
    description: str
    cvss_v3_score: Optional[float]
    cvss_v3_vector: str
    severity: str
    published: Optional[datetime]
    last_modified: Optional[datetime]
    cpe_products: str
    references: str
    remediation: str
    cwe: str
    kev: bool = False
    kev_date: Optional[datetime] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None


class CVEImportResult(BaseModel):
    imported: int
    updated: int
    files_processed: int
    message: str


# ---- SMTP / email ----
class SmtpConfigIn(BaseModel):
    host: str = ""
    port: int = 587
    username: str = ""
    password: Optional[str] = None  # None/"" => keep existing
    from_addr: str = ""
    use_tls: bool = True
    use_ssl: bool = False
    default_recipients: str = ""
    enabled: bool = False


class SmtpConfigOut(BaseModel):
    host: str
    port: int
    username: str
    from_addr: str
    use_tls: bool
    use_ssl: bool
    default_recipients: str
    enabled: bool
    has_password: bool


class EmailReportRequest(BaseModel):
    recipients: Optional[str] = None  # comma-separated; falls back to default_recipients
    formats: List[str] = ["pdf", "csv"]
    test: bool = False
