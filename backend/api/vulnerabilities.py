import ast
import os
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload
from typing import List, Optional
from uuid import UUID

from backend.database.session import get_db
from backend.models.models import Vulnerability, File, Project, User
from backend.models.schemas import VulnerabilityOut, VulnerabilityUpdate, ApplyFixResponse
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
    _, corrected_snippet, _, auto_fixable = generate_patched_code(finding, full_file_content)
    
    vuln.suggested_fix = corrected_snippet
    vuln.auto_fixable = auto_fixable
    db.commit()
    db.refresh(vuln)
    return vuln


@router.post("/{vuln_id}/apply-fix", response_model=ApplyFixResponse)
def apply_vulnerability_fix(
    vuln_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Applies the suggested fix to the actual file on disk.
    Searches for an exact match of vulnerability.code_snippet in the file content.
    If found exactly once: replaces it with vulnerability.suggested_fix, writes
    the updated file atomically to disk, sets vulnerability.fixed = True, and commits to DB.
    Returns 409 Conflict if found 0 or >1 times, or if already marked fixed.
    Returns 422 Unprocessable Entity if auto_fixable is False.
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

    if not vuln.auto_fixable:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="This finding doesn't have an automatically-applicable fix. Please review the recommendation and update the code manually."
        )

    if vuln.fixed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This vulnerability is already marked as fixed."
        )

    if not vuln.code_snippet or vuln.suggested_fix is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Could not locate the original code in the current file — it may have already been modified. Try regenerating the fix or editing manually."
        )

    project_id = vuln.file.project_id
    base_upload_dir = os.path.abspath(settings.UPLOAD_DIR)
    project_dir = os.path.abspath(os.path.join(base_upload_dir, str(project_id)))
    full_file_path = os.path.abspath(os.path.join(project_dir, vuln.file.filepath))

    # Path traversal validation
    if not full_file_path.startswith(project_dir) or not full_file_path.startswith(base_upload_dir):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Invalid file path"
        )

    if not os.path.exists(full_file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Source file not found on disk"
        )

    try:
        with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
            file_content = f.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read original source code: {e}"
        )

    match_count = file_content.count(vuln.code_snippet)

    if match_count == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Could not locate the original code in the current file — it may have already been modified. Try regenerating the fix or editing manually."
        )

    if match_count > 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This code pattern appears multiple times in the file — automatic fix application isn't safe here. Please edit manually using the suggested fix as a reference."
        )

    # --- Bug B Fix: Newline preservation ---
    # If the original snippet ended with '\n', ensure the replacement also ends
    # with exactly one '\n'.  Without this, if suggested_fix lacks a trailing
    # newline the very next line in the file gets concatenated onto the last
    # line of the fix, producing a syntax error (two statements on one line).
    snippet_had_trailing_newline = vuln.code_snippet.endswith("\n")
    fix_to_apply = vuln.suggested_fix
    if snippet_had_trailing_newline:
        if not fix_to_apply.endswith("\n"):
            fix_to_apply = fix_to_apply + "\n"
    else:
        # If the original did NOT end with \n, strip any spurious trailing
        # newline that was added by the generator so the replacement is
        # character-for-character compatible with the original boundary.
        fix_to_apply = fix_to_apply.rstrip("\n")

    new_content = file_content.replace(vuln.code_snippet, fix_to_apply, 1)

    # --- Bug B Fix: AST pre-write syntax validation (Python files only) ---
    # Parse the resulting file content with Python's ast.parse() BEFORE writing
    # to disk.  If the fix would produce invalid Python syntax we block the
    # write entirely rather than corrupting the source file.
    if full_file_path.endswith(".py"):
        try:
            ast.parse(new_content, filename=full_file_path)
        except SyntaxError as syntax_err:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "The generated fix would produce invalid Python syntax. "
                    "This fix has been blocked to prevent corrupting your file. "
                    "Please try regenerating the fix or edit manually. "
                    f"(SyntaxError at line {syntax_err.lineno}: {syntax_err.msg})"
                )
            )

    # Atomic write to temp file first, then os.replace
    dir_name = os.path.dirname(full_file_path)
    temp_file_path = os.path.join(dir_name, f".tmp_{vuln.file.id.hex}_{os.path.basename(full_file_path)}")

    try:
        with open(temp_file_path, "w", encoding="utf-8") as tf:
            tf.write(new_content)
        os.replace(temp_file_path, full_file_path)
    except Exception as e:
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update file on disk: {e}"
        )

    new_size = len(new_content.encode("utf-8"))
    vuln.file.size = new_size
    vuln.fixed = True

    db.commit()
    db.refresh(vuln)
    db.refresh(vuln.file)

    return {
        "vulnerability": vuln,
        "file": {
            "id": vuln.file.id,
            "size": vuln.file.size
        }
    }

