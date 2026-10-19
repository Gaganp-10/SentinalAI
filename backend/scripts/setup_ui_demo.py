import os
import sys
import json
from datetime import datetime, timedelta
from uuid import uuid4

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.database.session import SessionLocal
from backend.models.models import User, Project, ScanHistory, ScanFinding, File
from backend.utils.security import get_password_hash

def setup_ui_demo():
    db = SessionLocal()
    try:
        email = "demo_step8@sentinel.ai"
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(
                id=uuid4(),
                username="demo_step8",
                email=email,
                hashed_password=get_password_hash("Password123!"),
                is_active=True
            )
            db.add(user)
            db.commit()
            print(f"Created demo user: {email} / Password123!")
        else:
            user.hashed_password = get_password_hash("Password123!")
            db.commit()
            print(f"Updated demo user password: {email}")

        project = db.query(Project).filter(Project.project_name == "Step 8 Live Diff Project", Project.user_id == user.id).first()
        if not project:
            project = Project(
                id=uuid4(),
                project_name="Step 8 Live Diff Project",
                user_id=user.id
            )
            db.add(project)
            db.commit()
            print(f"Created project: {project.id}")
        else:
            print(f"Using existing project: {project.id}")

        # Add files to project
        files = [
            File(id=uuid4(), project_id=project.id, filename="app.py", filepath="app.py", size=500),
            File(id=uuid4(), project_id=project.id, filename="index.js", filepath="index.js", size=300),
            File(id=uuid4(), project_id=project.id, filename="requirements.txt", filepath="requirements.txt", size=100),
        ]
        db.query(File).filter(File.project_id == project.id).delete()
        db.add_all(files)
        db.commit()

        # Clean existing scans for clean state
        existing_scans = db.query(ScanHistory).filter(ScanHistory.project_id == project.id).all()
        for s in existing_scans:
            db.query(ScanFinding).filter(ScanFinding.scan_id == s.id).delete()
            db.delete(s)
        db.commit()

        # BASE SCAN (Scan 0)
        base_scan = ScanHistory(
            id=uuid4(),
            project_id=project.id,
            status="completed",
            scan_time=datetime.utcnow() - timedelta(minutes=60),
            total_issues=3,
            engines_run=json.dumps(["bandit", "ast", "semgrep", "osv"])
        )
        db.add(base_scan)
        db.commit()

        sf_base_1 = ScanFinding(
            id=uuid4(), scan_id=base_scan.id, project_id=project.id,
            fingerprint="fp_sql_injection_app_py_12",
            file_path="app.py", line_number=12, type="SQL Injection",
            severity="critical", source_tools='["bandit"]'
        )
        sf_base_2 = ScanFinding(
            id=uuid4(), scan_id=base_scan.id, project_id=project.id,
            fingerprint="fp_cmd_injection_app_py_17",
            file_path="app.py", line_number=17, type="Command Injection",
            severity="high", source_tools='["bandit"]'
        )
        sf_base_3 = ScanFinding(
            id=uuid4(), scan_id=base_scan.id, project_id=project.id,
            fingerprint="fp_hash_app_py_21",
            file_path="app.py", line_number=21, type="Insecure Hash",
            severity="medium", source_tools='["bandit"]'
        )
        db.add_all([sf_base_1, sf_base_2, sf_base_3])
        db.commit()

        # SCAN 2A: 2 Fixes applied (resolved=2, persisting=1)
        scan_2a = ScanHistory(
            id=uuid4(),
            project_id=project.id,
            status="completed",
            scan_time=datetime.utcnow() - timedelta(minutes=45),
            total_issues=1,
            engines_run=json.dumps(["bandit", "ast", "semgrep", "osv"])
        )
        db.add(scan_2a)
        db.commit()
        sf_2a_1 = ScanFinding(
            id=uuid4(), scan_id=scan_2a.id, project_id=project.id,
            fingerprint="fp_hash_app_py_21",
            file_path="app.py", line_number=21, type="Insecure Hash",
            severity="medium", source_tools='["bandit"]'
        )
        db.add(sf_2a_1)
        db.commit()

        # SCAN 2B: Regression re-introduced (regressed=1)
        scan_2b = ScanHistory(
            id=uuid4(),
            project_id=project.id,
            status="completed",
            scan_time=datetime.utcnow() - timedelta(minutes=30),
            total_issues=2,
            engines_run=json.dumps(["bandit", "ast", "semgrep", "osv"])
        )
        db.add(scan_2b)
        db.commit()
        sf_2b_1 = ScanFinding(
            id=uuid4(), scan_id=scan_2b.id, project_id=project.id,
            fingerprint="fp_hash_app_py_21",
            file_path="app.py", line_number=21, type="Insecure Hash",
            severity="medium", source_tools='["bandit"]'
        )
        sf_2b_2 = ScanFinding(
            id=uuid4(), scan_id=scan_2b.id, project_id=project.id,
            fingerprint="fp_cmd_injection_app_py_17",
            file_path="app.py", line_number=17, type="Command Injection",
            severity="high", source_tools='["bandit"]'
        )
        db.add_all([sf_2b_1, sf_2b_2])
        db.commit()

        # BASE FOR 2D: had a Semgrep JS finding
        scan_2d_base = ScanHistory(
            id=uuid4(),
            project_id=project.id,
            status="completed",
            scan_time=datetime.utcnow() - timedelta(minutes=15),
            total_issues=1,
            engines_run=json.dumps(["bandit", "semgrep", "osv"])
        )
        db.add(scan_2d_base)
        db.commit()
        sf_2d_base = ScanFinding(
            id=uuid4(), scan_id=scan_2d_base.id, project_id=project.id,
            fingerprint="fp_js_eval_index_js_2",
            file_path="index.js", line_number=2, type="DOM XSS",
            severity="high", source_tools='["semgrep"]'
        )
        db.add(sf_2d_base)
        db.commit()

        # SCAN 2D: Semgrep failed / did not run (engines_run=["bandit", "osv"])
        scan_2d = ScanHistory(
            id=uuid4(),
            project_id=project.id,
            status="completed",
            scan_time=datetime.utcnow() - timedelta(minutes=5),
            total_issues=0,
            engines_run=json.dumps(["bandit", "osv"]) # Semgrep missing!
        )
        db.add(scan_2d)
        db.commit()

        print(f"\nSETUP COMPLETE!")
        print(f"Project URL: http://localhost:3000/projects/{project.id}")
        print(f"Scan 2a ID: {scan_2a.id} (vs base {base_scan.id})")
        print(f"Scan 2b ID: {scan_2b.id} (vs scan 2a {scan_2a.id})")
        print(f"Scan 2d ID: {scan_2d.id} (vs base {scan_2d_base.id})")

    finally:
        db.close()

if __name__ == "__main__":
    setup_ui_demo()
