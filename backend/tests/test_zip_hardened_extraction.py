import io
import os
import stat
import zipfile
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.models import Project, User, File as DBFile
from backend.utils.security import get_password_hash, create_access_token

@pytest.fixture
def test_context(db):
    user = User(
        email="zip_sec_test@example.com",
        username="zipsectester",
        hashed_password=get_password_hash("password123"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    project = Project(
        project_name="Zip Security Project",
        user_id=user.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}
    return project, headers


def test_reject_sibling_prefix_path(client, test_context):
    """Archives with ../<project>-evil/x.py must be rejected (400)."""
    project, headers = test_context
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"../{project.id}-evil/malicious.py", "print('hacked')\n")
    
    response = client.post(
        f"/api/projects/{project.id}/files",
        headers=headers,
        files={"file": ("sibling_attack.zip", buf.getvalue(), "application/zip")},
    )
    assert response.status_code == 400
    assert "Zip-Slip" in response.text or "path traversal" in response.text.lower()


def test_reject_absolute_path(client, test_context):
    """Archives with absolute paths (/evil.py) must be rejected (400)."""
    project, headers = test_context
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("/evil.py", "print('absolute')\n")
    
    response = client.post(
        f"/api/projects/{project.id}/files",
        headers=headers,
        files={"file": ("abs_attack.zip", buf.getvalue(), "application/zip")},
    )
    assert response.status_code == 400
    assert "absolute path" in response.text.lower() or "Zip-Slip" in response.text


def test_reject_drive_letter_path(client, test_context):
    """Archives with drive letters (C:\\evil.py or C:/evil.py) must be rejected (400)."""
    project, headers = test_context
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("C:/evil.py", "print('drive letter')\n")
    
    response = client.post(
        f"/api/projects/{project.id}/files",
        headers=headers,
        files={"file": ("drive_attack.zip", buf.getvalue(), "application/zip")},
    )
    assert response.status_code == 400
    assert "drive letter" in response.text.lower() or "Zip-Slip" in response.text


def test_reject_backslash_path(client, test_context):
    """Archives with Windows backslash tricks (sub\\evil.py) must be rejected (400)."""
    project, headers = test_context
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("subdir/evil.py", "print('backslash')\n")
    # Replace forward slash with backslash in raw archive header bytes so orig_filename has backslash
    raw_zip = buf.getvalue().replace(b"subdir/evil.py", b"subdir\\evil.py")

    response = client.post(
        f"/api/projects/{project.id}/files",
        headers=headers,
        files={"file": ("backslash_attack.zip", raw_zip, "application/zip")},
    )
    assert response.status_code == 400
    assert "backslash" in response.text.lower() or "Zip-Slip" in response.text


def test_skip_symlink_entry(client, test_context, db):
    """Symlink entries inside a ZIP archive must be skipped, not extracted."""
    project, headers = test_context
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        # Add normal file
        z.writestr("app.py", "print('valid')\n")
        
        # Add symlink entry
        symlink_info = zipfile.ZipInfo("symlink_to_passwd.py")
        symlink_info.create_system = 3  # Unix
        # S_IFLNK | 0777
        symlink_info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(symlink_info, "/etc/passwd")

    response = client.post(
        f"/api/projects/{project.id}/files",
        headers=headers,
        files={"file": ("symlink_test.zip", buf.getvalue(), "application/zip")},
    )
    assert response.status_code == 201
    extracted = response.json()
    extracted_names = [f["filename"] for f in extracted]
    assert "app.py" in extracted_names
    assert "symlink_to_passwd.py" not in extracted_names


def test_reject_forged_header_sizes(client, test_context, monkeypatch):
    """
    If header claims a tiny size (e.g. 50 bytes) but actual decompressed bytes
    exceed per-file limit, stream copying must detect it and abort (400).
    """
    project, headers = test_context
    # Temporarily set MAX_UPLOAD_SIZE_MB = 1 (1MB) to test without massive memory
    from backend.utils.config import settings
    monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE_MB", 1)

    # 1.5MB of data
    large_data = b"A" * (1500 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        info = zipfile.ZipInfo("forged.py")
        info.file_size = 50  # Lie in the header!
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, large_data)

    response = client.post(
        f"/api/projects/{project.id}/files",
        headers=headers,
        files={"file": ("forged_header.zip", buf.getvalue(), "application/zip")},
    )
    assert response.status_code == 400
    assert "exceeded" in response.text.lower() or "limit" in response.text.lower()


def test_reject_ratio_bomb(client, test_context, monkeypatch):
    """
    Archives with extreme compression ratio exceeding MAX_ZIP_RATIO must be rejected (400).
    """
    project, headers = test_context
    from backend.utils.config import settings
    # Set limit to 20.0 ratio threshold
    monkeypatch.setattr(settings, "MAX_ZIP_RATIO", 20.0)

    # Highly compressible zero-byte sequence (2MB expanding from few hundred bytes)
    bomb_data = b"\x00" * (2 * 1024 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("zeros.py", bomb_data)

    response = client.post(
        f"/api/projects/{project.id}/files",
        headers=headers,
        files={"file": ("ratio_bomb.zip", buf.getvalue(), "application/zip")},
    )
    assert response.status_code == 400
    assert "ratio" in response.text.lower() or "bomb" in response.text.lower()


def test_reject_too_many_files(client, test_context, monkeypatch):
    """
    Archives containing more files than MAX_ZIP_FILES must be rejected (400).
    """
    project, headers = test_context
    from backend.utils.config import settings
    monkeypatch.setattr(settings, "MAX_ZIP_FILES", 5)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(10):
            z.writestr(f"file_{i}.py", f"print({i})\n")

    response = client.post(
        f"/api/projects/{project.id}/files",
        headers=headers,
        files={"file": ("too_many_files.zip", buf.getvalue(), "application/zip")},
    )
    assert response.status_code == 400
    assert "file count limit" in response.text.lower() or "exceeds" in response.text.lower()
