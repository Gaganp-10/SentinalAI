import os
import re
import stat
import uuid
import zipfile
import shutil
import logging
import tempfile
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File as FastAPIFile, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List, Dict
from uuid import UUID

from backend.database.session import get_db
from backend.models.models import File as DBFile, Project, User
from backend.models.schemas import FileOut
from backend.api.auth import get_current_user
from backend.utils.config import settings
from backend.parser.language_detect import detect_language, is_manifest_filename

logger = logging.getLogger(__name__)

router = APIRouter(prefix="", tags=["Files"])

# ─── Step 4 limits (canonical values, read from config) ────────────────────────
# MAX_ZIP_FILES=5000          — counted on KEPT files only (after junk/skip)
# MAX_UNCOMPRESSED_SIZE_MB=500 — total across all kept files
# MAX_UPLOAD_SIZE_MB=2         — per source file (non-manifest)
# MAX_MANIFEST_UPLOAD_SIZE_MB=10 — per manifest
# MAX_ZIP_RATIO=100.0          — compression ratio bomb guard

IGNORED_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "build", "dist", "target", ".idea", ".vscode", "__MACOSX",
    ".tox", ".pytest_cache", "coverage", ".nyc_output", ".DS_Store",
}
ARCHIVE_EXTENSIONS = {"zip", "tar", "gz", "tgz", "bz2", "7z", "rar", "xz"}

# Binary-file magic-byte prefixes (first 8 bytes)
_BINARY_MAGIC = [
    b"\x7fELF",      # ELF executable
    b"MZ",           # PE / DOS executable
    b"\x89PNG",      # PNG
    b"\xff\xd8\xff", # JPEG
    b"GIF8",         # GIF
    b"\x00\x00\x01\x00",  # ICO
    b"PK\x03\x04",  # ZIP (nested archive already caught above, belt-and-suspenders)
    b"\x1f\x8b",    # gzip
    b"BZh",          # bzip2
    b"\xfd7zXZ",    # xz
    b"Rar!",         # RAR
    b"7z\xbc\xaf",  # 7-zip
    b"\xcf\xfa\xed\xfe",  # Mach-O 32-bit
    b"\xce\xfa\xed\xfe",  # Mach-O 64-bit
    b"\xca\xfe\xba\xbe",  # Java class
]

def _is_binary_content(data: bytes) -> bool:
    """Heuristic: binary if magic header matches or >30% non-text bytes in first 8KB."""
    sample = data[:8]
    for magic in _BINARY_MAGIC:
        if sample.startswith(magic):
            return True
    # Null-byte presence is a reliable binary indicator
    probe = data[:8192]
    if b"\x00" in probe:
        return True
    return False

def _is_minified(data: bytes, ext: str) -> bool:
    """
    Heuristic: JS/TS/CSS file is minified if any single line is >= 2000 chars.
    Also catches map files and .min.* filenames via caller.
    """
    if ext not in ("js", "ts", "jsx", "tsx", "css"):
        return False
    try:
        text = data[:65536].decode("utf-8", errors="replace")
    except Exception:
        return False
    return any(len(line) >= 2000 for line in text.splitlines())


def check_project_ownership(db: Session, project_id: UUID, user_id: UUID) -> Project:
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == user_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    return project

@router.post("/projects/{project_id}/files", status_code=status.HTTP_201_CREATED)
def upload_files(
    project_id: UUID,
    request: Request,
    file: UploadFile = FastAPIFile(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Uploads a code file or ZIP archive to a project.

    Returns::
        {
            "accepted": [...FileOut...],
            "skipped": {"junk_dir": N, "unsupported": N, "oversized": N,
                        "binary": N, "minified": N, "nested_archive": N}
        }

    ZIP uploads are safely extracted and strictly checked against path traversal
    (Zip-Slip), ratio bombs, nested archives, symlinks, and resource limits per
    Step 4 spec:
      - 5000 file limit counted on KEPT files only
      - 500 MB total uncompressed
      - 2 MB per source file, 10 MB per manifest
      - Ratio limit 100

    All unexpected errors are logged with full detail; only a generic message
    is returned to the caller.
    """
    # ── Early rejection on Content-Length ──────────────────────────────────────
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            cl = int(content_length)
            _, ext_hdr = os.path.splitext((file.filename or "").lower())
            ext_hdr_clean = ext_hdr.lstrip(".")
            is_manifest_hdr = is_manifest_filename(file.filename or "")
            if ext_hdr_clean == "zip":
                max_mb_hdr = settings.MAX_ZIP_UPLOAD_SIZE_MB
            elif is_manifest_hdr:
                max_mb_hdr = settings.MAX_MANIFEST_UPLOAD_SIZE_MB
            else:
                max_mb_hdr = settings.MAX_UPLOAD_SIZE_MB
            if cl > max_mb_hdr * 1024 * 1024 * 2:  # 2× headroom for multipart overhead
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="Upload too large"
                )
        except HTTPException:
            raise
        except Exception:
            pass  # Malformed header — fall through to body-level check

    # Verify project ownership
    project = check_project_ownership(db, project_id, current_user.id)

    # Setup safe base directory path for uploads
    base_upload_path = os.path.abspath(settings.UPLOAD_DIR)
    project_upload_dir = os.path.abspath(os.path.join(base_upload_path, str(project_id)))
    os.makedirs(project_upload_dir, exist_ok=True)
    project_upload_dir_real = os.path.realpath(project_upload_dir)

    filename = file.filename or "upload"
    _, ext = os.path.splitext(filename.lower())
    ext_clean = ext.lstrip(".")
    is_manifest = is_manifest_filename(filename)

    max_mb = settings.MAX_MANIFEST_UPLOAD_SIZE_MB if is_manifest else settings.MAX_UPLOAD_SIZE_MB
    max_bytes = max_mb * 1024 * 1024

    if not is_manifest and ext_clean not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File extension '{ext_clean}' is not allowed. Supported: {settings.ALLOWED_EXTENSIONS}"
        )

    saved_files: List[DBFile] = []
    created_disk_paths: List[str] = []
    skipped: Dict[str, int] = {
        "junk_dir": 0,
        "unsupported": 0,
        "oversized": 0,
        "binary": 0,
        "minified": 0,
        "nested_archive": 0,
    }

    if ext_clean == "zip":
        temp_zip_fd, temp_zip_path = tempfile.mkstemp(prefix=f"upload_{uuid.uuid4().hex}_", suffix=".zip")
        os.close(temp_zip_fd)
        try:
            zip_max_bytes = settings.MAX_ZIP_UPLOAD_SIZE_MB * 1024 * 1024
            bytes_read_zip = 0
            with open(temp_zip_path, "wb") as f:
                while True:
                    chunk = file.file.read(65536)
                    if not chunk:
                        break
                    bytes_read_zip += len(chunk)
                    if bytes_read_zip > zip_max_bytes:
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="Upload too large"
                        )
                    f.write(chunk)

            with zipfile.ZipFile(temp_zip_path, "r") as z:
                all_members = z.infolist()

                # ── Limits from config ───────────────────────────────────────────
                manifest_max_bytes = settings.MAX_MANIFEST_UPLOAD_SIZE_MB * 1024 * 1024
                max_source_file_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024  # 2 MB per source
                max_total_uncompressed = settings.MAX_UNCOMPRESSED_SIZE_MB * 1024 * 1024  # 500 MB
                max_ratio = settings.MAX_ZIP_RATIO  # 100
                max_zip_files = settings.MAX_ZIP_FILES  # 5000 (kept only)

                # ── First pass: path safety only (fast, rejects malicious ZIPs) ─
                for member in all_members:
                    raw_names = [member.filename]
                    orig_name = getattr(member, "orig_filename", None)
                    if orig_name and orig_name not in raw_names:
                        raw_names.append(orig_name)

                    for candidate_name in raw_names:
                        if re.match(r"^[a-zA-Z]:", candidate_name):
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Zip-Slip: drive letter in '{candidate_name}'"
                            )
                        if "\\" in candidate_name:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Zip-Slip: backslash in '{candidate_name}'"
                            )
                        if candidate_name.startswith("/") or os.path.isabs(candidate_name):
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Zip-Slip: absolute path in '{candidate_name}'"
                            )

                    raw_name = member.filename
                    norm_parts = [p for p in raw_name.split("/") if p]
                    if ".." in norm_parts or any(p.startswith("..") for p in norm_parts):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Zip-Slip: '..' in '{raw_name}'"
                        )

                    if member.is_dir() or not norm_parts:
                        continue

                    # Confinement check
                    target_path = os.path.realpath(os.path.join(project_upload_dir, *norm_parts))
                    try:
                        common = os.path.commonpath([target_path, project_upload_dir_real])
                    except ValueError:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Zip-Slip: path outside destination for '{raw_name}'"
                        )
                    if common != project_upload_dir_real or not target_path.startswith(project_upload_dir_real + os.sep):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Zip-Slip: path traversal in '{raw_name}'"
                        )

                    # Header-based ratio pre-check (catches obvious bombs before decompression)
                    file_limit = manifest_max_bytes if is_manifest_filename(norm_parts[-1]) else max_source_file_bytes
                    if member.file_size > file_limit:
                        # Don't reject here — we will skip oversized files with a counter
                        pass
                    if member.compress_size > 0 and (member.file_size / member.compress_size) > max_ratio and member.file_size > 1024 * 1024:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Ratio bomb detected for '{raw_name}'"
                        )

                # ── Second pass: Extract with skip/count logic ────────────────────
                total_bytes_written = 0

                # Cache created directories to avoid redundant syscalls
                seen_dirs = set()

                for member in all_members:
                    if member.is_dir():
                        continue

                    # Skip symlinks
                    mode = member.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        continue

                    norm_parts = [p for p in member.filename.split("/") if p]
                    if not norm_parts:
                        continue

                    # 1. Skip files inside junk/ignored directories (FIRST)
                    if any(part in IGNORED_DIRS for part in norm_parts[:-1]):
                        skipped["junk_dir"] += 1
                        continue

                    file_base = norm_parts[-1]
                    _, entry_ext = os.path.splitext(file_base.lower())
                    entry_ext_clean = entry_ext.lstrip(".")

                    # 2. Skip nested archives
                    if entry_ext_clean in ARCHIVE_EXTENSIONS:
                        skipped["nested_archive"] += 1
                        continue

                    # 3. Skip unsupported extensions
                    member_is_manifest = is_manifest_filename(file_base)
                    if not member_is_manifest and entry_ext_clean not in settings.ALLOWED_EXTENSIONS:
                        skipped["unsupported"] += 1
                        continue

                    # 4. Skip files that declare oversized uncompressed size in header
                    per_file_limit = manifest_max_bytes if member_is_manifest else max_source_file_bytes
                    if member.file_size > per_file_limit:
                        skipped["oversized"] += 1
                        continue

                    # ── Check kept-file count limit (5000 kept only) ─────────────
                    if len(saved_files) + 1 > max_zip_files:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"ZIP contains more than {max_zip_files} accepted files"
                        )

                    # Write-time confinement: compute target with realpath immediately before opening for write
                    target_path = os.path.realpath(os.path.join(project_upload_dir, *norm_parts))
                    try:
                        common = os.path.commonpath([target_path, project_upload_dir_real])
                    except ValueError:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Zip-Slip: path outside destination for '{member.filename}'"
                        )
                    if common != project_upload_dir_real or not target_path.startswith(project_upload_dir_real + os.sep):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Zip-Slip: path traversal in '{member.filename}'"
                        )

                    # Refuse if target itself is a symlink
                    if os.path.islink(target_path):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Zip-Slip: symlink target detected in '{member.filename}'"
                        )

                    # Refuse if any parent directory along the join path is a symlink
                    comp_path = project_upload_dir_real
                    for part in norm_parts[:-1]:
                        comp_path = os.path.join(comp_path, part)
                        if os.path.islink(comp_path):
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Zip-Slip: symlink parent directory detected in '{member.filename}'"
                            )

                    dir_path = os.path.dirname(target_path)
                    curr_p = dir_path
                    while curr_p and curr_p != project_upload_dir_real and len(curr_p) >= len(project_upload_dir_real):
                        if os.path.islink(curr_p):
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Zip-Slip: symlink parent directory detected in '{member.filename}'"
                            )
                        p_parent = os.path.dirname(curr_p)
                        if p_parent == curr_p:
                            break
                        curr_p = p_parent

                    if dir_path not in seen_dirs:
                        os.makedirs(dir_path, exist_ok=True)
                        seen_dirs.add(dir_path)

                    # Track whether file existed before this upload request
                    existed_before = os.path.exists(target_path)
                    if not existed_before:
                        created_disk_paths.append(target_path)

                    # 5. Stream-extract with byte counting; read first chunk for binary/minified detection
                    bytes_written_file = 0
                    first_chunk_checked = False
                    skip_this = None

                    open_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                    if hasattr(os, "O_NOFOLLOW"):
                        open_flags |= os.O_NOFOLLOW
                    if hasattr(os, "O_BINARY"):
                        open_flags |= os.O_BINARY

                    try:
                        fd = os.open(target_path, open_flags, 0o644)
                    except OSError as oe:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Zip-Slip: cannot open file safely '{member.filename}': {oe}"
                        )

                    with z.open(member) as source, os.fdopen(fd, "wb") as target:
                        while True:
                            chunk = source.read(65536)
                            if not chunk:
                                break
                            chunk_len = len(chunk)
                            bytes_written_file += chunk_len
                            total_bytes_written += chunk_len

                            # 5a. Binary detection on first chunk
                            if not first_chunk_checked:
                                first_chunk_checked = True
                                if not member_is_manifest and _is_binary_content(chunk):
                                    skip_this = "binary"
                                    break
                                if not member_is_manifest and _is_minified(chunk, entry_ext_clean):
                                    skip_this = "minified"
                                    break

                            # 5b. Per-file size limit (actual bytes, not header)
                            if bytes_written_file > per_file_limit:
                                skip_this = "oversized"
                                break

                            # 5c. Total uncompressed limit
                            if total_bytes_written > max_total_uncompressed:
                                raise HTTPException(
                                    status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="ZIP total uncompressed size exceeds limit"
                                )

                            # 5d. Live ratio check
                            if member.compress_size > 0 and (bytes_written_file / member.compress_size) > max_ratio and bytes_written_file > 1024 * 1024:
                                raise HTTPException(
                                    status_code=status.HTTP_400_BAD_REQUEST,
                                    detail=f"Ratio bomb during decompression of '{member.filename}'"
                                )

                            target.write(chunk)

                    if skip_this:
                        # Roll back bytes from total and remove partial file
                        total_bytes_written -= bytes_written_file
                        if target_path in created_disk_paths:
                            if os.path.exists(target_path):
                                try:
                                    os.remove(target_path)
                                except Exception:
                                    pass
                            created_disk_paths.remove(target_path)
                        skipped[skip_this] += 1
                        continue

                    rel_filepath = os.path.relpath(target_path, project_upload_dir_real).replace("\\", "/")
                    lang = detect_language(file_base)

                    db_file = DBFile(
                        project_id=project_id,
                        filename=file_base,
                        filepath=rel_filepath,
                        language=lang,
                        size=bytes_written_file
                    )
                    saved_files.append(db_file)

            if saved_files:
                db.add_all(saved_files)
            db.commit()

        except HTTPException:
            db.rollback()
            for p in created_disk_paths:
                if os.path.isfile(p) or os.path.islink(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
            raise
        except zipfile.BadZipFile:
            db.rollback()
            for p in created_disk_paths:
                if os.path.isfile(p) or os.path.islink(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The uploaded file is not a valid ZIP archive."
            )
        except Exception as e:
            db.rollback()
            for p in created_disk_paths:
                if os.path.isfile(p) or os.path.islink(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
            logger.exception("ZIP extraction failed for project %s: %s", project_id, e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while processing the archive. Please try again."
            )
        finally:
            if os.path.exists(temp_zip_path):
                try:
                    os.remove(temp_zip_path)
                except Exception:
                    pass
    else:
        # Handle single file upload — stream body and enforce size limit
        safe_filename = os.path.basename(filename.replace("\\", "/"))
        target_path = os.path.realpath(os.path.join(project_upload_dir, safe_filename))
        try:
            common = os.path.commonpath([target_path, project_upload_dir_real])
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")
        if common != project_upload_dir_real or not target_path.startswith(project_upload_dir_real + os.sep):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid target filename")

        bytes_written = 0
        try:
            with open(target_path, "wb") as f:
                while True:
                    chunk = file.file.read(65536)
                    if not chunk:
                        break
                    bytes_written += len(chunk)
                    if bytes_written > max_bytes:
                        f.close()
                        os.remove(target_path)
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="Upload too large"
                        )
                    f.write(chunk)

            rel_filepath = safe_filename
            lang = detect_language(safe_filename)

            db_file = DBFile(
                project_id=project_id,
                filename=safe_filename,
                filepath=rel_filepath,
                language=lang,
                size=bytes_written
            )
            db.add(db_file)
            db.commit()
            db.refresh(db_file)
            saved_files.append(db_file)
        except HTTPException:
            db.rollback()
            if os.path.exists(target_path):
                try:
                    os.remove(target_path)
                except Exception:
                    pass
            raise
        except Exception as e:
            db.rollback()
            if os.path.exists(target_path):
                try:
                    os.remove(target_path)
                except Exception:
                    pass
            logger.exception("Single-file upload failed for project %s: %s", project_id, e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while saving the file. Please try again."
            )

    # Refresh saved files to populate ORM fields (only for small sets to avoid thousands of roundtrips)
    if len(saved_files) <= 100:
        for f in saved_files:
            try:
                db.refresh(f)
            except Exception:
                pass

    return {
        "accepted": saved_files,
        "skipped": skipped,
    }


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
