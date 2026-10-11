import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import json
import shutil
from uuid import uuid4
from fastapi.testclient import TestClient

from backend.main import app
from backend.database.session import Base, get_db
from backend.tests.conftest import TestingSessionLocal, engine
from backend.models.models import User, Project, File as DBFile, ScanHistory
from backend.api.auth import create_access_token
from backend.api.scans import run_background_scan
from backend.utils.config import settings

import backend.database.session as session_module
import backend.api.scans as scans_module
import backend.api.auth as auth_module

session_module.SessionLocal = TestingSessionLocal
scans_module.SessionLocal = TestingSessionLocal
auth_module.SessionLocal = TestingSessionLocal

def override_get_db():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()

app.dependency_overrides[get_db] = override_get_db

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
db = TestingSessionLocal()

# 2. Setup user and project
user = User(
    id=uuid4(),
    username="semgrep_fail_demo",
    email="fail_demo@example.com",
    hashed_password="mock"
)
db.add(user)
db.commit()

project = Project(
    id=uuid4(),
    user_id=user.id,
    project_name="Semgrep Failure Project"
)
db.add(project)
db.commit()

# Create a project dir with a python file
project_dir = os.path.abspath(os.path.join(settings.UPLOAD_DIR, str(project.id)))
os.makedirs(project_dir, exist_ok=True)
sample_file_path = os.path.join(project_dir, "app.py")
with open(sample_file_path, "w", encoding="utf-8") as f:
    f.write("import os\nprint('hello world')\n")

db_file = DBFile(
    id=uuid4(),
    project_id=project.id,
    filename="app.py",
    filepath="app.py",
    language="python",
    size=30
)
db.add(db_file)
db.commit()

scan = ScanHistory(
    id=uuid4(),
    project_id=project.id,
    status="pending"
)
db.add(scan)
db.commit()

# 3. Simulate Semgrep failure by pointing rules_path to a non-existent or invalid configuration
from unittest.mock import patch
from backend.detectors.schema import DetectorError

def failing_semgrep_scan(self, pdir):
    raise DetectorError("Semgrep execution failed with exit code 2: semgrep: error: rule configuration file not found or corrupted: /invalid/rules.yaml")

with patch("backend.detectors.semgrep_detector.SemgrepDetector.scan", failing_semgrep_scan):
    run_background_scan(project.id, scan.id)

# 4. Fetch the real scan response via TestClient API endpoint
token = create_access_token(subject=str(user.id))
client = TestClient(app)
resp = client.get(f"/api/scans/{scan.id}", headers={"Authorization": f"Bearer {token}"})

print("HTTP STATUS:", resp.status_code)
print("ACTUAL SCAN RESPONSE JSON:")
print(json.dumps(resp.json(), indent=2))
