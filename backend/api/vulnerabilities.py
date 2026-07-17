import os
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload
from typing import List, Optional
from uuid import UUID

from backend.database.session import get_db
from backend.models.models import Vulnerability, File, Project, User
from backend.models.schemas import VulnerabilityOut, VulnerabilityUpdate
from backend.api.auth import get_current_user
from backend.utils.config import settings

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

@router.get("", response_model=List[VulnerabilityOut])
def list_vulnerabilities(
    project_id: UUID,
    severity: Optional[str] = None,
    type: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves, searches, and filters findings for a specific project.
    Verifies that the current user owns the project.
    """
    # Verify project ownership
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )

    query = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.file))
        .join(File)
        .filter(File.project_id == project_id)
    )

    if severity:
        query = query.filter(Vulnerability.severity == severity.lower())
    if type:
        query = query.filter(Vulnerability.type == type)
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            Vulnerability.description.ilike(search_filter)
            | Vulnerability.type.ilike(search_filter)
            | Vulnerability.cwe_id.ilike(search_filter)
            | Vulnerability.owasp_category.ilike(search_filter)
            | File.filename.ilike(search_filter)
        )

    return query.all()


@router.get("/{vuln_id}", response_model=VulnerabilityOut)
def get_vulnerability(
    vuln_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns a single vulnerability by ID, including its parent file metadata.
    Verifies that the vulnerability belongs to a project owned by the current user.
    """
    vuln = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.file))
        .join(File)
        .join(Project)
        .filter(
            Vulnerability.id == vuln_id,
            Project.user_id == current_user.id
        )
        .first()
    )
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    return vuln


@router.patch("/{vuln_id}", response_model=VulnerabilityOut)
def update_vulnerability_status(
    vuln_id: UUID,
    vuln_update: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Marks a vulnerability as fixed or unfixed.
    """
    vuln = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.file))
        .join(File)
        .join(Project)
        .filter(
            Vulnerability.id == vuln_id,
            Project.user_id == current_user.id
        )
        .first()
    )
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    vuln.fixed = vuln_update.fixed
    db.commit()
    db.refresh(vuln)
    return vuln


@router.post("/{vuln_id}/regenerate-fix", response_model=VulnerabilityOut)
def regenerate_vulnerability_fix(
    vuln_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Triggers AI-regeneration of the secure fix code block for the vulnerability.
    """
    vuln = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.file))
        .join(File)
        .join(Project)
        .filter(
            Vulnerability.id == vuln_id,
            Project.user_id == current_user.id
        )
        .first()
    )
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
        
    # Find original file source
    project_id = vuln.file.project_id
    project_dir = os.path.abspath(os.path.join(settings.UPLOAD_DIR, str(project_id)))
    full_file_path = os.path.join(project_dir, vuln.file.filepath)
    
    full_file_content = ""
    if os.path.exists(full_file_path):
        try:
            with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
                full_file_content = f.read()
        except Exception as file_err:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to read original source code: {file_err}"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source file not found on disk"
        )
        
    # Reconstruct temporary finding schema
    from backend.detectors.schema import Finding
    finding = Finding(
        file_path=vuln.file.filepath,
        line_number=vuln.line_number,
        type=vuln.type,
        severity=vuln.severity,
        description=vuln.description,
        code_snippet=vuln.code_snippet,
        cwe_id=vuln.cwe_id,
        owasp_category=vuln.owasp_category,
        confidence=vuln.confidence,
        source_tool=vuln.source_tool
    )
    
    # Regenerate secure code block
    from backend.fixer.fix_generator import generate_patched_code
    _, corrected_snippet, _ = generate_patched_code(finding, full_file_content)
    
    vuln.suggested_fix = corrected_snippet
    db.commit()
    db.refresh(vuln)
    return vuln
