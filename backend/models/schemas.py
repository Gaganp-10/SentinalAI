from pydantic import BaseModel, EmailStr, model_validator, field_validator
from typing import Optional, List, Any
from uuid import UUID
from datetime import datetime

from backend.utils.security import validate_password_strength

# --- Auth Schemas ---
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        """Enforce shared password rules at the schema level (returns 422 on violation)."""
        return validate_password_strength(v)

class UserOut(BaseModel):
    id: UUID
    username: str
    email: EmailStr
    created_at: datetime
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    username: str  # Can be username or email
    password: str

class GoogleAuthRequest(BaseModel):
    access_token: str

# --- Password Reset Schemas ---
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        """Reuse the same rules as signup so there is a single source of truth."""
        return validate_password_strength(v)

# --- Project Schemas ---
class ProjectCreate(BaseModel):
    project_name: str

class ProjectOut(BaseModel):
    id: UUID
    user_id: UUID
    project_name: str
    scan_date: Optional[datetime] = None

    class Config:
        from_attributes = True

# --- File Schemas ---
class FileOut(BaseModel):
    id: UUID
    project_id: UUID
    filename: str
    filepath: str
    language: Optional[str] = None
    size: int

    class Config:
        from_attributes = True

# --- Vulnerability Schemas ---
class VulnerabilityOut(BaseModel):
    id: UUID
    file_id: UUID
    file: Optional[FileOut] = None  # nested file relation for UI breadcrumbs/filename
    type: str
    line_number: int
    severity: str
    description: str
    recommendation: Optional[str] = None
    explanation: Optional[str] = None  # auto-populated from recommendation at serialization
    code_snippet: Optional[str] = None
    suggested_fix: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: float
    source_tool: str
    fixed: bool
    auto_fixable: bool = True
    fix_source: Optional[str] = None  # "template" | "ai" | None

    class Config:
        from_attributes = True

    @model_validator(mode='after')
    def populate_explanation(self) -> 'VulnerabilityOut':
        """Mirror recommendation → explanation so the frontend 'explanation' field is always populated."""
        if self.explanation is None and self.recommendation is not None:
            self.explanation = self.recommendation
        return self

class VulnerabilityUpdate(BaseModel):
    fixed: bool


class FileMetadataOut(BaseModel):
    id: UUID
    size: int

    class Config:
        from_attributes = True


class ApplyFixResponse(BaseModel):
    vulnerability: VulnerabilityOut
    file: FileMetadataOut
    apply_status: str = "applied"  # "applied" | "verified" | "rolled_back"



import json

# --- Scan History Schemas ---
class DependencySummary(BaseModel):
    checked: int = 0
    not_checked: int = 0
    manifests: int = 0


class ScanHistoryOut(BaseModel):
    id: UUID
    project_id: UUID
    scan_time: datetime
    total_issues: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    status: str
    warnings: Optional[List[str]] = None
    dependency_summary: Optional[DependencySummary] = None

    class Config:
        from_attributes = True

    @field_validator("warnings", mode="before")
    @classmethod
    def parse_warnings(cls, v: Any) -> Optional[List[str]]:
        if v is None:
            return None
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                return [v] if v else []
        if isinstance(v, list):
            return [str(x) for x in v]
        return None

    @field_validator("dependency_summary", mode="before")
    @classmethod
    def parse_dependency_summary(cls, v: Any) -> Optional[Any]:
        if v is None:
            return None
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return None
        return v

# --- AI Mentor Schemas ---
class MentorQuestion(BaseModel):
    question: str

class MentorAnswer(BaseModel):
    answer: str
