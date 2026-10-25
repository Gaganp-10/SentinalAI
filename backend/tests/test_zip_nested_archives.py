import io
import os
import zipfile
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.models import Project, User, File as DBFile
from backend.utils.security import get_password_hash, create_access_token

def test_nested_zip_archives_are_not_extracted(client, db):
    """
    Step 4 spec verification:
    When an uploaded ZIP contains a nested archive (e.g. inner.zip containing hidden.py),
    nested archives must NOT be extracted.
    hidden.py must not exist on disk or in the database.
    """
    # 1. Create a test user and project
    user = User(
        email="zip_test@example.com",
        username="ziptester",
        hashed_password=get_password_hash("password123"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    project = Project(
        project_name="Zip Test Project",
        user_id=user.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    token = create_access_token(user.id)
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Build an inner zip containing a hidden python file
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w", zipfile.ZIP_DEFLATED) as inner_zip:
        inner_zip.writestr("hidden_nested_file.py", "print('this should never be extracted')\n")
    inner_bytes = inner_buffer.getvalue()

    # 3. Build an outer zip containing a regular file and the nested inner zip
    outer_buffer = io.BytesIO()
    with zipfile.ZipFile(outer_buffer, "w", zipfile.ZIP_DEFLATED) as outer_zip:
        outer_zip.writestr("valid_app.py", "print('hello from outer zip')\n")
        outer_zip.writestr("nested_archive.zip", inner_bytes)
    outer_bytes = outer_buffer.getvalue()

    # 4. Upload the outer zip
    response = client.post(
        f"/api/projects/{project.id}/files",
        headers=headers,
        files={"file": ("test_package.zip", outer_bytes, "application/zip")},
    )

    assert response.status_code == 201, f"Upload failed: {response.text}"
    files_data = response.json()

    # 5. Verify extracted filenames
    extracted_filenames = [f["filename"] for f in files_data]
    assert "valid_app.py" in extracted_filenames

    # CRITICAL: hidden_nested_file.py from inner.zip must NOT be extracted or registered
    assert "hidden_nested_file.py" not in extracted_filenames

    # Check DB records
    db_records = db.query(DBFile).filter(DBFile.project_id == project.id).all()
    db_filenames = [f.filename for f in db_records]
    assert "valid_app.py" in db_filenames
    assert "hidden_nested_file.py" not in db_filenames

    # Check disk paths to confirm hidden_nested_file.py does NOT exist
    project_upload_dir = os.path.join("uploads", str(project.id))
    hidden_on_disk = os.path.join(project_upload_dir, "hidden_nested_file.py")
    assert not os.path.exists(hidden_on_disk), "Nested archive file was erroneously extracted to disk!"
