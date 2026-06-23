"""Database models.

Schema overview:
  User      - operator accounts
  Target    - a host / range / asset to assess
  Scan      - one scan job against a target (queued -> running -> completed/failed)
  Host      - a host discovered during a scan
  Service   - an open port/service on a host (product + version + cpe)
  CVE        - a vulnerability record imported from NVD feeds (local DB)
  Finding   - correlation between a discovered Service and a CVE (the actual vuln on the asset)
"""
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), default="operator")  # admin | operator | viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SmtpConfig(Base):
    """SMTP settings for emailing reports — configured in the GUI (single row, id=1)."""
    __tablename__ = "smtp_config"
    id = Column(Integer, primary_key=True)
    host = Column(String(255), default="")
    port = Column(Integer, default=587)
    username = Column(String(255), default="")
    password = Column(String(512), default="")
    from_addr = Column(String(255), default="")
    use_tls = Column(Boolean, default=True)
    use_ssl = Column(Boolean, default=False)
    default_recipients = Column(Text, default="")  # comma-separated
    enabled = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=datetime.utcnow)


class CveUpdateConfig(Base):
    """Periodic CVE auto-update settings (single row, id=1), managed from the GUI."""
    __tablename__ = "cve_update_config"
    id = Column(Integer, primary_key=True)
    enabled = Column(Boolean, default=False)
    interval_hours = Column(Integer, default=24)
    source = Column(String(16), default="online")  # online | feed_dir
    last_run = Column(DateTime, nullable=True)
    last_status = Column(String(16), default="never")  # ok | error | running | never
    last_message = Column(Text, default="")
    last_added = Column(Integer, default=0)


class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    address = Column(String(255), nullable=False)  # IP, hostname, or CIDR range
    description = Column(Text, default="")
    tags = Column(String(255), default="")  # comma-separated
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    scan_type = Column(String(32), default="full")  # discovery | full | port | custom
    profile = Column(String(255), default="")  # nmap flags actually used
    status = Column(String(32), default="queued", index=True)  # queued|running|completed|failed
    progress = Column(Integer, default=0)
    error = Column(Text, default="")
    raw_output = Column(Text, default="")  # raw nmap XML/stdout for audit
    log = Column(Text, default="")  # live, shell-like progress log appended during the scan
    created_by = Column(String(64), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    target = relationship("Target", back_populates="scans")
    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    web_findings = relationship("WebFinding", back_populates="scan", cascade="all, delete-orphan")
    packages = relationship("Package", back_populates="scan", cascade="all, delete-orphan")


class Host(Base):
    __tablename__ = "hosts"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    address = Column(String(255), nullable=False)
    hostname = Column(String(255), default="")
    state = Column(String(32), default="up")
    os_guess = Column(String(255), default="")

    scan = relationship("Scan", back_populates="hosts")
    services = relationship("Service", back_populates="host", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(8), default="tcp")
    state = Column(String(32), default="open")
    service_name = Column(String(128), default="")
    product = Column(String(255), default="")
    version = Column(String(128), default="")
    cpe = Column(String(512), default="")
    banner = Column(Text, default="")

    host = relationship("Host", back_populates="services")
    findings = relationship("Finding", back_populates="service", cascade="all, delete-orphan")


class CVE(Base):
    __tablename__ = "cves"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(32), unique=True, nullable=False, index=True)
    description = Column(Text, default="")
    cvss_v3_score = Column(Float, nullable=True)
    cvss_v3_vector = Column(String(128), default="")
    cvss_v2_score = Column(Float, nullable=True)
    severity = Column(String(16), default="UNKNOWN", index=True)  # CRITICAL/HIGH/MEDIUM/LOW/NONE
    published = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)
    # Affected products: pipe-separated "vendor:product:version" tokens parsed from CPE configs.
    cpe_products = Column(Text, default="")
    # Structured affected ranges (JSON list) parsed from NVD CPE configurations:
    # [{"p": product, "v": exactVersion, "vs": startVer, "vsi": startIncl,
    #   "ve": endVer, "vei": endIncl}] — used for precise version-range matching.
    affected = Column(Text, default="")
    references = Column(Text, default="")  # newline-separated URLs
    remediation = Column(Text, default="")  # guidance (derived/curated)
    cwe = Column(String(64), default="")


class Package(Base):
    """Full installed-package inventory captured by a credentialed (SSH) scan.

    Every package on the host is stored (not only vulnerable ones), each annotated
    with the highest criticality, matched CVE ids, and aggregated patching remedy.
    """
    __tablename__ = "packages"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=True)
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(128), default="")        # upstream version used for matching
    full_version = Column(String(255), default="")   # full distro version string
    manager = Column(String(16), default="")          # dpkg | rpm
    status = Column(String(16), default="ok", index=True)  # vulnerable | ok
    max_severity = Column(String(16), default="NONE", index=True)
    max_cvss = Column(Float, nullable=True)
    cve_count = Column(Integer, default=0)
    cve_ids = Column(Text, default="")                # comma-separated
    remediation = Column(Text, default="")

    scan = relationship("Scan", back_populates="packages")


class WebFinding(Base):
    """Findings from URL / web-application penetration testing.

    These are misconfiguration / disclosure / TLS / injection-indicator findings
    that are not necessarily tied to a CVE (though software-fingerprint findings
    may reference one).
    """
    __tablename__ = "web_findings"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    target_url = Column(String(1024), default="")
    category = Column(String(64), default="")  # Security Header|TLS|Information Disclosure|Cookie|Software|Injection|Method
    name = Column(String(255), default="")
    severity = Column(String(16), default="INFO", index=True)  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(32), default="")  # optional, for software-fingerprint findings
    description = Column(Text, default="")
    evidence = Column(Text, default="")
    remediation = Column(Text, default="")
    references = Column(Text, default="")
    status = Column(String(32), default="open", index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="web_findings")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "service_id", "cve_id", name="uq_finding"),)
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    service_id = Column(Integer, ForeignKey("services.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String(32), nullable=False, index=True)
    severity = Column(String(16), default="UNKNOWN", index=True)
    cvss_score = Column(Float, nullable=True)
    match_confidence = Column(String(16), default="medium")  # high|medium|low
    # Free-form (host + package + multi-CVE remedy + caveats) — can exceed 255 chars.
    match_reason = Column(Text, default="")
    status = Column(String(32), default="open", index=True)  # open|confirmed|false_positive|fixed|accepted
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
    service = relationship("Service", back_populates="findings")
