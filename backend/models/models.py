import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Float, ForeignKey, Text, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from backend.database.session import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

    projects = relationship("Project", back_populates="user", cascade="all, delete-orphan")
    password_reset_tokens = relationship(
        "PasswordResetToken", back_populates="user", cascade="all, delete-orphan"
    )


class Project(Base):
    __tablename__ = "projects"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    project_name = Column(String, nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="projects")
    files = relationship("File", back_populates="project", cascade="all, delete-orphan")
    scan_histories = relationship("ScanHistory", back_populates="project", cascade="all, delete-orphan")


class File(Base):
    __tablename__ = "files"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String, nullable=False)
    filepath = Column(String, nullable=False)
    language = Column(String, nullable=True)
    size = Column(Integer, nullable=False)  # in bytes

    project = relationship("Project", back_populates="files")
    vulnerabilities = relationship("Vulnerability", back_populates="file", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_id = Column(UUID(as_uuid=True), ForeignKey("files.id", ondelete="CASCADE"), nullable=False)
    type = Column(String, nullable=False)
    line_number = Column(Integer, nullable=False)
    severity = Column(String, nullable=False)  # enum: critical/high/medium/low/info
    description = Column(String, nullable=False)
    recommendation = Column(String, nullable=True)
    code_snippet = Column(String, nullable=True)
    suggested_fix = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
    owasp_category = Column(String, nullable=True)
    confidence = Column(Float, default=1.0)
    source_tool = Column(String, nullable=False)  # bandit/semgrep/ast/ai
    fixed = Column(Boolean, default=False)
    auto_fixable = Column(Boolean, default=True)
    # Tracks which subsystem produced the applied fix:
    #   "template" = deterministic rule-based fix (proven safe, applied without re-scan)
    #   "ai"       = LLM-generated fix (applied only after re-scan confirms vulnerability gone)
    #   None       = not yet fixed
    fix_source = Column(String, nullable=True)

    file = relationship("File", back_populates="vulnerabilities")


class ScanHistory(Base):
    __tablename__ = "scan_history"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    scan_time = Column(DateTime, default=datetime.utcnow)
    total_issues = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    status = Column(String, nullable=False)  # enum: pending/running/completed/failed
    warnings = Column(Text, nullable=True)  # JSON-encoded list of warning strings
    dependency_summary = Column(Text, nullable=True)  # JSON-encoded dict: {"checked": N, "not_checked": M, "manifests": K}
    engines_run = Column(Text, nullable=True)  # JSON-encoded list of engine names: ["bandit", "ast", "semgrep", "osv"]

    project = relationship("Project", back_populates="scan_histories")
    scan_findings = relationship("ScanFinding", back_populates="scan", cascade="all, delete-orphan", passive_deletes=True)


class ScanFinding(Base):
    """
    Historical snapshot of findings detected in each completed scan.
    Retained for the 20 most recent scans per project to enable regression detection
    and scan diff comparisons.
    """
    __tablename__ = "scan_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_history.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint = Column(String(128), nullable=False, index=True)
    file_path = Column(String, nullable=False)
    type = Column(String, nullable=False)
    issue_class = Column(String, nullable=True)
    rule_id = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    line_number = Column(Integer, nullable=False, default=1)
    source_tools = Column(Text, nullable=False, default="[]")  # JSON text list e.g. ["bandit", "semgrep"]
    vulnerability_id = Column(UUID(as_uuid=True), nullable=True)
    package_name = Column(String, nullable=True)
    package_version = Column(String, nullable=True)
    fixed_by_apply_fix = Column(Boolean, default=False)

    scan = relationship("ScanHistory", back_populates="scan_findings")
    project = relationship("Project")


class PasswordResetToken(Base):
    """
    Stores SHA-256 hashes of password-reset tokens.

    The raw token is NEVER persisted; only its SHA-256 hash is stored.
    The raw token travels in the reset URL to the user's email client and
    is verified by re-hashing the submitted value and doing a hash lookup.

    Lifecycle:
      - created_at / expires_at:  token is valid until expires_at
      - used_at (nullable):        set to now() when the token is consumed;
                                   any token with used_at IS NOT NULL is rejected
    """

    __tablename__ = "password_reset_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # SHA-256 hex digest of the raw token — unique and indexed for fast lookup
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)  # set on first (and only) use

    user = relationship("User", back_populates="password_reset_tokens")
