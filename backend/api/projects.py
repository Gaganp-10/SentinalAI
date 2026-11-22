from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from uuid import UUID

from backend.database.session import get_db
from backend.models.models import Project, User
from backend.models.schemas import ProjectCreate, ProjectOut, DeletionConfirmationRequest
from backend.api.auth import get_current_user, verify_google_token
from backend.utils.security import verify_password
from backend.utils.config import settings

router = APIRouter(prefix="/projects", tags=["Projects"])

@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    project_in: ProjectCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Creates a new security scan project for the current authenticated user.
    """
    if settings.MAX_PROJECTS_PER_USER is not None and settings.MAX_PROJECTS_PER_USER >= 0:
        existing_count = db.query(Project).filter(Project.user_id == current_user.id).count()
        if existing_count >= settings.MAX_PROJECTS_PER_USER:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Project limit reached. Maximum allowed projects per user is {settings.MAX_PROJECTS_PER_USER}."
            )

    project = Project(
        project_name=project_in.project_name,
        user_id=current_user.id
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("", response_model=List[ProjectOut])
def list_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists all projects belonging to the current user.
    """
    projects = db.query(Project).filter(Project.user_id == current_user.id).all()
    return projects


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves details of a specific project.
    """
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    return project


@router.delete("/{project_id}", status_code=status.HTTP_200_OK)
async def delete_project(
    project_id: UUID,
    request: Request,
    password: Optional[str] = None,
    google_token: Optional[str] = None,
    confirmation: Optional[DeletionConfirmationRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Permanently deletes a project, all its scan history, findings, and disk files.
    Requires password confirmation for password accounts, or a fresh Google token for OAuth accounts.
    Builds disk paths only from validated UUIDs inside the upload root without following symlinks.
    """
    import os
    import shutil
    import uuid

    # Support confirmation via request body, query params, or custom confirmation header
    confirm_pw = (confirmation.password if confirmation else None) or password or request.headers.get("x-confirm-password")
    confirm_google = (confirmation.google_token if confirmation else None) or google_token or request.headers.get("x-confirm-google-token")

    if current_user.hashed_password:
        if not confirm_pw or not verify_password(confirm_pw, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password confirmation."
            )
    else:
        if not confirm_google:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Fresh Google token required for project deletion."
            )
        token_data = await verify_google_token(confirm_google)
        if token_data.get("email", "").lower() != current_user.email.lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google token does not match the account email."
            )

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )

    # Strictly build disk path using only the validated UUID
    proj_uuid = uuid.UUID(str(project.id))
    upload_root = os.path.realpath(os.path.abspath(settings.UPLOAD_DIR))
    project_dir = os.path.realpath(os.path.join(upload_root, str(proj_uuid)))

    if os.path.dirname(project_dir) == upload_root and os.path.exists(project_dir):
        if os.path.islink(project_dir):
            os.unlink(project_dir)
        elif os.path.isdir(project_dir):
            shutil.rmtree(project_dir, ignore_errors=True)

    db.delete(project)
    db.commit()
    return {"detail": "Project and all associated files deleted successfully"}
