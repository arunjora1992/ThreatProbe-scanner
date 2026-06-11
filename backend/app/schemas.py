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
