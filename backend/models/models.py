import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Float, ForeignKey, Text
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

    project = relationship("Project", back_populates="scan_histories")
