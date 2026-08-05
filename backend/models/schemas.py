from pydantic import BaseModel, EmailStr, model_validator
from typing import Optional, List, Any
from uuid import UUID
from datetime import datetime

# --- Auth Schemas ---
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

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



# --- Scan History Schemas ---
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

    class Config:
        from_attributes = True

# --- AI Mentor Schemas ---
class MentorQuestion(BaseModel):
    question: str

class MentorAnswer(BaseModel):
    answer: str
