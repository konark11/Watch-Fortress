"""
Core database models.

Default storage is SQLite (portable mode - matches the "SQLite (portable
mode)" requirement and lets the whole platform run from one file with zero
external services). Swapping to PostgreSQL for a multi-analyst production
deployment is a one-line change: set DATABASE_URL=postgresql://... and the
same models/queries work unmodified since we stay within SQLAlchemy Core
types supported by both engines.
"""
from __future__ import annotations
import os
import enum
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, DateTime, Text,
    ForeignKey, JSON, Enum as SAEnum, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

DATABASE_URL = os.environ.get("VULN_DATABASE_URL", "sqlite:///" + os.path.join(os.path.dirname(__file__), "..", "data", "vuln_platform.db"))

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def now_utc():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Users / RBAC / Audit
# ---------------------------------------------------------------------------
class Role(str, enum.Enum):
    ADMINISTRATOR = "administrator"
    SECURITY_ANALYST = "security_analyst"
    PENETRATION_TESTER = "penetration_tester"
    AUDITOR = "auditor"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(SAEnum(Role), nullable=False, default=Role.SECURITY_ANALYST)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now_utc)
    last_login = Column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String(80))
    action = Column(String(120))          # e.g. "scan.launch", "report.generate", "finding.status_change"
    target = Column(String(255))          # e.g. "scan:42", "asset:10.0.0.5"
    details = Column(Text)
    ip_address = Column(String(64))
    timestamp = Column(DateTime, default=now_utc, index=True)


# ---------------------------------------------------------------------------
# Asset Inventory
# ---------------------------------------------------------------------------
class Criticality(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(64), index=True)
    hostname = Column(String(255), nullable=True)
    os_name = Column(String(255), nullable=True)
    os_accuracy = Column(Integer, nullable=True)
    criticality = Column(SAEnum(Criticality), default=Criticality.MEDIUM)
    internet_exposed = Column(Boolean, default=False)
    tags = Column(JSON, default=list)
    notes = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=now_utc)
    last_seen = Column(DateTime, default=now_utc)

    ports = relationship("Port", back_populates="asset", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("ip_address", name="uq_asset_ip"),)


class Port(Base):
    __tablename__ = "ports"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    port_number = Column(Integer)
    protocol = Column(String(10), default="tcp")
    state = Column(String(20), default="open")
    service_name = Column(String(120), nullable=True)
    product = Column(String(255), nullable=True)
    version = Column(String(120), nullable=True)
    banner = Column(Text, nullable=True)

    asset = relationship("Asset", back_populates="ports")


class SSLCertificate(Base):
    __tablename__ = "ssl_certificates"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    port_number = Column(Integer)
    subject = Column(String(500), nullable=True)
    issuer = Column(String(500), nullable=True)
    valid_from = Column(String(64), nullable=True)
    valid_to = Column(String(64), nullable=True)
    self_signed = Column(Boolean, default=False)
    expired = Column(Boolean, default=False)


# ---------------------------------------------------------------------------
# Scans / Scheduling
# ---------------------------------------------------------------------------
class ScannerType(str, enum.Enum):
    NMAP = "nmap"
    OPENVAS = "openvas"
    NESSUS = "nessus"
    NUCLEI = "nuclei"
    CUSTOM = "custom"
    IMPORT = "import"   # results uploaded from a file rather than launched


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    scanner_type = Column(SAEnum(ScannerType))
    target = Column(String(500))
    status = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    progress_pct = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_by = Column(String(80), nullable=True)
    schedule_id = Column(Integer, ForeignKey("scan_schedules.id"), nullable=True)
    raw_output_path = Column(String(500), nullable=True)
    error_message = Column(Text, nullable=True)
    findings_count = Column(Integer, default=0)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class ScheduleFrequency(str, enum.Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM_CRON = "custom_cron"


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"
    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    scanner_type = Column(SAEnum(ScannerType))
    target = Column(String(500))
    frequency = Column(SAEnum(ScheduleFrequency))
    cron_expression = Column(String(120), nullable=True)   # used when frequency == CUSTOM_CRON
    enabled = Column(Boolean, default=True)
    rescan_on_remediation = Column(Boolean, default=False)
    created_by = Column(String(80), nullable=True)
    created_at = Column(DateTime, default=now_utc)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)


# ---------------------------------------------------------------------------
# Findings (raw, per-scanner) and Vulnerabilities (correlated/merged)
# ---------------------------------------------------------------------------
class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(Base):
    """A single raw finding as reported by ONE scanner, before correlation.
    Multiple Findings (possibly from different scanners) can point to the
    same Vulnerability after the correlation engine runs."""
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)
    scanner_source = Column(SAEnum(ScannerType))
    asset_ip = Column(String(64), index=True)
    port_number = Column(Integer, nullable=True)
    title = Column(String(500))
    description = Column(Text, nullable=True)
    severity = Column(SAEnum(Severity), default=Severity.INFO)
    cvss_score = Column(Float, nullable=True)
    cve_ids = Column(JSON, default=list)
    plugin_id = Column(String(120), nullable=True)   # Nessus plugin ID / OpenVAS OID / Nuclei template ID
    solution = Column(Text, nullable=True)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=now_utc)

    scan = relationship("Scan", back_populates="findings")


class VulnStatus(str, enum.Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"


class Vulnerability(Base):
    """A correlated/deduplicated vulnerability - the unit the dashboard,
    risk engine, and report generator actually work with. One Vulnerability
    may be backed by several raw Findings from different scanners."""
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    canonical_title = Column(String(500))
    description = Column(Text, nullable=True)
    severity = Column(SAEnum(Severity), default=Severity.INFO)
    cvss_score = Column(Float, nullable=True)
    risk_score = Column(Float, default=0.0)       # 0-100, see correlation/risk_scoring.py
    cve_ids = Column(JSON, default=list)
    cwe_ids = Column(JSON, default=list)
    capec_ids = Column(JSON, default=list)
    attack_techniques = Column(JSON, default=list)
    owasp_categories = Column(JSON, default=list)
    exploit_available = Column(Boolean, default=False)
    kev_listed = Column(Boolean, default=False)     # CISA Known Exploited Vulnerabilities catalog
    port_number = Column(Integer, nullable=True)
    affected_service = Column(String(255), nullable=True)
    remediation = Column(Text, nullable=True)
    status = Column(SAEnum(VulnStatus), default=VulnStatus.OPEN)
    source_scanners = Column(JSON, default=list)     # which scanner types contributed
    contributing_finding_ids = Column(JSON, default=list)
    first_seen = Column(DateTime, default=now_utc)
    last_seen = Column(DateTime, default=now_utc)
    assigned_to = Column(String(80), nullable=True)

    asset = relationship("Asset", back_populates="vulnerabilities")


# ---------------------------------------------------------------------------
# Knowledge Base (RAG-indexed)
# ---------------------------------------------------------------------------
class KBCategory(str, enum.Enum):
    PLAYBOOK = "playbook"
    VULN_WRITEUP = "vulnerability_writeup"
    REMEDIATION_GUIDE = "remediation_guide"
    POLICY = "organization_policy"
    LESSONS_LEARNED = "lessons_learned"


class KnowledgeDoc(Base):
    __tablename__ = "knowledge_docs"
    id = Column(Integer, primary_key=True)
    title = Column(String(255))
    category = Column(SAEnum(KBCategory))
    content = Column(Text)
    tags = Column(JSON, default=list)
    created_by = Column(String(80), nullable=True)
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
class ReportType(str, enum.Enum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"


class ReportFormat(str, enum.Enum):
    PDF = "pdf"
    HTML = "html"
    DOCX = "docx"
    JSON = "json"


class ReportJob(Base):
    __tablename__ = "report_jobs"
    id = Column(Integer, primary_key=True)
    report_type = Column(SAEnum(ReportType))
    report_format = Column(SAEnum(ReportFormat))
    scope_description = Column(String(500), nullable=True)
    generated_by = Column(String(80), nullable=True)
    generated_at = Column(DateTime, default=now_utc)
    file_path = Column(String(500), nullable=True)
    compliance_framework = Column(String(80), nullable=True)  # PCI-DSS | ISO27001 | NIST_CSF


# ---------------------------------------------------------------------------
# Threat Intelligence
# ---------------------------------------------------------------------------
class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    CVE = "cve"


class ThreatIOC(Base):
    """An indicator of compromise the organization actually encountered
    (from an incident, phishing campaign, threat feed, etc.) - not a
    live scan result. related_cves is what powers the "vulnerabilities
    this adversary is known to target" correlation against our own
    Vulnerability table; latitude/longitude (IP IOCs only, best-effort)
    is what powers the threat-hunter map."""
    __tablename__ = "threat_iocs"
    id = Column(Integer, primary_key=True)
    ioc_type = Column(SAEnum(IOCType))
    value = Column(String(500), index=True)
    threat_actor = Column(String(255), nullable=True)
    campaign = Column(String(255), nullable=True)
    source = Column(String(500), nullable=True)
    related_cves = Column(JSON, default=list)
    confidence = Column(String(20), default="medium")
    notes = Column(Text, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    created_by = Column(String(80), nullable=True)
    created_at = Column(DateTime, default=now_utc)


def init_db():
    os.makedirs(os.path.join(os.path.dirname(__file__), "..", "data"), exist_ok=True)
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
