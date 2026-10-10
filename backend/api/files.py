import os
import zipfile
import shutil
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File as FastAPIFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List
from uuid import UUID

from backend.database.session import get_db
from backend.models.models import File as DBFile, Project, User
from backend.models.schemas import FileOut
from backend.api.auth import get_current_user
from backend.utils.config import settings
from backend.parser.language_detect import detect_language, is_manifest_filename

router = APIRouter(prefix="", tags=["Files"])

def check_project_ownership(db: Session, project_id: UUID, user_id: UUID) -> Project:
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == user_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    return project

@router.post("/projects/{project_id}/files", response_model=List[FileOut], status_code=status.HTTP_201_CREATED)
def upload_files(
    project_id: UUID,
    file: UploadFile = FastAPIFile(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Uploads a code file or ZIP archive to a project.
    ZIP uploads are safely extracted and checked against path traversal (Zip-Slip).
    """
    # Verify project ownership
    project = check_project_ownership(db, project_id, current_user.id)
    
    # Setup safe base directory path for uploads
    base_upload_path = os.path.abspath(settings.UPLOAD_DIR)
    project_upload_dir = os.path.abspath(os.path.join(base_upload_path, str(project_id)))
    os.makedirs(project_upload_dir, exist_ok=True)
    
    # Validate file size
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)
    
    filename = file.filename
    _, ext = os.path.splitext(filename.lower())
    ext_clean = ext.lstrip(".")
    is_manifest = is_manifest_filename(filename)
    
    max_mb = settings.MAX_MANIFEST_UPLOAD_SIZE_MB if is_manifest else settings.MAX_UPLOAD_SIZE_MB
    max_bytes = max_mb * 1024 * 1024
    if file_size > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload size of {max_mb}MB"
        )
    
    if not is_manifest and ext_clean not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File extension '{ext_clean}' is not allowed. Supported: {settings.ALLOWED_EXTENSIONS}"
        )
        
    saved_files = []
    IGNORED_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "build", "dist", "target", ".idea", ".vscode"}
    
    if ext_clean == "zip":
        temp_zip_path = os.path.join(project_upload_dir, f"temp_{filename}")
        try:
            with open(temp_zip_path, "wb") as f:
                f.write(file.file.read())
                
            with zipfile.ZipFile(temp_zip_path, "r") as z:
                # 1. First pass: Validate paths to avoid path traversal (Zip-Slip)
                for member_name in z.namelist():
                    # Combine path and check it remains under project_upload_dir
                    target_path = os.path.abspath(os.path.join(project_upload_dir, member_name))
                    if not target_path.startswith(project_upload_dir):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Zip-Slip vulnerability check failed for entry '{member_name}'"
                        )
                
                # 2. Second pass: Safely extract and save DB records
                manifest_max_bytes = settings.MAX_MANIFEST_UPLOAD_SIZE_MB * 1024 * 1024
                for member in z.infolist():
                    if member.is_dir():
                        continue
                    
                    normalized_parts = member.filename.replace("\\", "/").strip("/").split("/")
                    # Skip files inside ignored directories (e.g. node_modules)
                    if any(part in IGNORED_DIRS for part in normalized_parts[:-1]):
                        continue

                    member_is_manifest = is_manifest_filename(member.filename)
                    if member_is_manifest and member.file_size > manifest_max_bytes:
                        continue
                    
                    target_path = os.path.abspath(os.path.join(project_upload_dir, member.filename))
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    
                    with z.open(member) as source, open(target_path, "wb") as target:
                        shutil.copyfileobj(source, target)
                        
                    rel_filepath = os.path.relpath(target_path, project_upload_dir).replace("\\", "/")
                    lang = detect_language(member.filename)
                    
                    db_file = DBFile(
                        project_id=project_id,
                        filename=os.path.basename(member.filename),
                        filepath=rel_filepath,
                        language=lang,
                        size=member.file_size
                    )
                    db.add(db_file)
                    saved_files.append(db_file)
            db.commit()
            
        except HTTPException:
            db.rollback()
            raise
        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to extract and process ZIP file: {e}"
            )
        finally:
            if os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)
    else:
        # Handle single file upload
        target_path = os.path.abspath(os.path.join(project_upload_dir, filename))
        try:
            with open(target_path, "wb") as f:
                f.write(file.file.read())
                
            rel_filepath = filename
            lang = detect_language(filename)
            
            db_file = DBFile(
                project_id=project_id,
                filename=filename,
                filepath=rel_filepath,
                language=lang,
                size=file_size
            )
            db.add(db_file)
            db.commit()
            db.refresh(db_file)
            saved_files.append(db_file)
        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to write file to disk: {e}"
            )
            
    return saved_files


@router.get("/projects/{project_id}/files", response_model=List[FileOut])
def list_files(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists all files uploaded in a project.
    """
    check_project_ownership(db, project_id, current_user.id)
    files = db.query(DBFile).filter(DBFile.project_id == project_id).all()
    return files


@router.get("/files/{file_id}/download")
def download_file(
    file_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns the current file content (which may include applied fixes) as a downloadable file response.
    Verifies that the requesting user owns the project this file belongs to.
    """
    file_obj = (
        db.query(DBFile)
        .join(Project)
        .filter(
            DBFile.id == file_id,
            Project.user_id == current_user.id
        )
        .first()
    )
    if not file_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )

    base_upload_dir = os.path.abspath(settings.UPLOAD_DIR)
    project_dir = os.path.abspath(os.path.join(base_upload_dir, str(file_obj.project_id)))
    full_file_path = os.path.abspath(os.path.join(project_dir, file_obj.filepath))

    # Path traversal safety check
    if not full_file_path.startswith(project_dir) or not full_file_path.startswith(base_upload_dir):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Invalid file path"
        )

    if not os.path.isfile(full_file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File content not found on disk"
        )

    return FileResponse(
        path=full_file_path,
        filename=file_obj.filename,
        media_type="application/octet-stream"
    )
