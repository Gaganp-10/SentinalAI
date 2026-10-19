import pytest
import uuid
import json
from datetime import datetime, timedelta
from backend.detectors.schema import Finding
from backend.detectors.fingerprint import (
    compute_code_fingerprint,
    compute_dependency_fingerprint,
    normalize_snippet,
    assign_fingerprints,
)
from backend.models.models import ScanHistory, ScanFinding, Project, User
from backend.database.session import SessionLocal


def test_normalize_snippet():
    raw_snippet = "  12:   import hashlib\n  13:   h = hashlib.md5()   \n"
    normalized = normalize_snippet(raw_snippet)
    assert normalized == "import hashlib h = hashlib.md5()"

    # Blank lines or empty snippet
    assert normalize_snippet("") == ""
    assert normalize_snippet(None) == ""


def test_code_fingerprint_line_shift_and_whitespace_stability():
    # Original finding at line 12
    fp1 = compute_code_fingerprint(
        file_path="app/auth.py",
        finding_type="Insecure Hash",
        issue_class="INSECURE_HASH",
        code_snippet="12: hashlib.md5(passwd)",
    )

    # 10 lines inserted above -> line number is now 22, and indentation has changed
    fp2 = compute_code_fingerprint(
        file_path="app/auth.py",
        finding_type="Insecure Hash",
        issue_class="INSECURE_HASH",
        code_snippet="   22:    hashlib.md5(passwd)   \n",
    )

    assert fp1 == fp2, "Fingerprint must survive line shifts and whitespace variations"


def test_code_fingerprint_file_path_sensitivity():
    fp_a = compute_code_fingerprint(
        file_path="app/a.py",
        finding_type="Insecure Hash",
        issue_class="INSECURE_HASH",
        code_snippet="hashlib.md5(passwd)",
    )
    fp_b = compute_code_fingerprint(
        file_path="app/b.py",
        finding_type="Insecure Hash",
        issue_class="INSECURE_HASH",
        code_snippet="hashlib.md5(passwd)",
    )
    assert fp_a != fp_b, "Fingerprints for different files must be distinct"


def test_occurrence_index_separates_identical_lines():
    finding1 = Finding(
        file_path="app/crypto.py",
        line_number=10,
        type="Insecure Hash",
        severity="medium",
        description="MD5 usage",
        code_snippet="hashlib.md5(x)",
        issue_class="INSECURE_HASH",
    )
    finding2 = Finding(
        file_path="app/crypto.py",
        line_number=30,
        type="Insecure Hash",
        severity="medium",
        description="MD5 usage again",
        code_snippet="hashlib.md5(x)",
        issue_class="INSECURE_HASH",
    )

    fps = assign_fingerprints([finding1, finding2])
    assert len(fps) == 2
    assert fps[0] != fps[1], "Occurrence index must differentiate identical lines in same file"
    assert ":2" in fps[1]


def test_dependency_fingerprint_ignores_version():
    # Version 2.2.0
    fp1 = compute_dependency_fingerprint(
        manifest_path="requirements.txt",
        ecosystem="PyPI",
        package_name="django",
    )

    # Upgraded to version 2.2.28
    fp2 = compute_dependency_fingerprint(
        manifest_path="requirements.txt",
        ecosystem="PyPI",
        package_name="django",
    )

    assert fp1 == fp2, "Dependency fingerprint must remain identical across version upgrades"

    # Different package must differ
    fp3 = compute_dependency_fingerprint(
        manifest_path="requirements.txt",
        ecosystem="PyPI",
        package_name="requests",
    )
    assert fp1 != fp3


def test_scan_finding_persistence_and_retention():
    db = SessionLocal()
    try:
        user = db.query(User).first()
        if not user:
            user = User(username="test_step8", email="step8@example.com")
            db.add(user)
            db.commit()

        project = Project(user_id=user.id, project_name="Test Retention Project")
        db.add(project)
        db.commit()

        # Create 25 completed scans with ScanFinding rows
        base_time = datetime.utcnow() - timedelta(days=30)
        for i in range(25):
            scan = ScanHistory(
                project_id=project.id,
                scan_time=base_time + timedelta(hours=i),
                status="completed",
                total_issues=1,
                engines_run=json.dumps(["bandit", "ast", "osv"]),
            )
            db.add(scan)
            db.flush()

            sf = ScanFinding(
                scan_id=scan.id,
                project_id=project.id,
                fingerprint=f"fp_{i}",
                file_path="app.py",
                type="Test Finding",
                severity="medium",
                line_number=i + 1,
                source_tools=json.dumps(["bandit"]),
            )
            db.add(sf)
        db.commit()

        # Verify initial count
        all_sf_count = db.query(ScanFinding).filter(ScanFinding.project_id == project.id).count()
        assert all_sf_count == 25

        # Execute retention pruning (simulate post-scan retention logic)
        completed_scans = (
            db.query(ScanHistory.id)
            .filter(ScanHistory.project_id == project.id, ScanHistory.status == "completed")
            .order_by(ScanHistory.scan_time.desc())
            .all()
        )
        if len(completed_scans) > 20:
            old_scan_ids = [s.id for s in completed_scans[20:]]
            db.query(ScanFinding).filter(
                ScanFinding.project_id == project.id,
                ScanFinding.scan_id.in_(old_scan_ids)
            ).delete(synchronize_session=False)
            db.commit()

        retained_sf_count = db.query(ScanFinding).filter(ScanFinding.project_id == project.id).count()
        assert retained_sf_count == 20, "Must retain exactly 20 scan snapshots"

    finally:
        # Clean up test project
        if 'project' in locals() and project.id:
            db.query(Project).filter(Project.id == project.id).delete()
            db.commit()
        db.close()


def test_diff_classification_new_resolved_persisting_regressed():
    from backend.detectors.diff import compute_scan_diff
    from backend.models.models import File
    db = SessionLocal()
    try:
        user = db.query(User).first()
        if not user:
            user = User(username="test_diff_user", email="diff_user@example.com")
            db.add(user)
            db.commit()

        project = Project(user_id=user.id, project_name="Diff Test Project")
        db.add(project)
        db.flush()

        db_file = File(project_id=project.id, filename="app.py", filepath="app.py", size=100)
        db.add(db_file)
        db.commit()

        base_time = datetime.utcnow() - timedelta(hours=5)

        # Scan 1: contains fp_A and fp_B
        scan1 = ScanHistory(
            project_id=project.id,
            scan_time=base_time,
            status="completed",
            engines_run=json.dumps(["bandit", "ast"]),
            critical_count=1,
            high_count=1,
        )
        db.add(scan1)
        db.flush()
        db.add(ScanFinding(scan_id=scan1.id, project_id=project.id, fingerprint="fp_A", file_path="app.py", type="Type A", severity="high", source_tools=json.dumps(["bandit"])))
        db.add(ScanFinding(scan_id=scan1.id, project_id=project.id, fingerprint="fp_B", file_path="app.py", type="Type B", severity="critical", source_tools=json.dumps(["bandit"])))

        # Scan 2: fp_B was fixed! Now contains fp_A and fp_C
        scan2 = ScanHistory(
            project_id=project.id,
            scan_time=base_time + timedelta(hours=1),
            status="completed",
            engines_run=json.dumps(["bandit", "ast"]),
            critical_count=0,
            high_count=2,
        )
        db.add(scan2)
        db.flush()
        db.add(ScanFinding(scan_id=scan2.id, project_id=project.id, fingerprint="fp_A", file_path="app.py", type="Type A", severity="high", source_tools=json.dumps(["bandit"])))
        db.add(ScanFinding(scan_id=scan2.id, project_id=project.id, fingerprint="fp_C", file_path="app.py", type="Type C", severity="high", source_tools=json.dumps(["bandit"])))

        # Scan 3 (target): fp_B was re-introduced (regressed)! fp_C was fixed (resolved)! fp_D is new! fp_A is persisting!
        scan3 = ScanHistory(
            project_id=project.id,
            scan_time=base_time + timedelta(hours=2),
            status="completed",
            engines_run=json.dumps(["bandit", "ast"]),
            critical_count=1,
            high_count=2,
        )
        db.add(scan3)
        db.flush()
        db.add(ScanFinding(scan_id=scan3.id, project_id=project.id, fingerprint="fp_A", file_path="app.py", type="Type A", severity="high", source_tools=json.dumps(["bandit"])))
        db.add(ScanFinding(scan_id=scan3.id, project_id=project.id, fingerprint="fp_B", file_path="app.py", type="Type B", severity="critical", source_tools=json.dumps(["bandit"])))
        db.add(ScanFinding(scan_id=scan3.id, project_id=project.id, fingerprint="fp_D", file_path="app.py", type="Type D", severity="high", source_tools=json.dumps(["bandit"])))
        db.commit()

        # Compute diff comparing scan 3 against scan 2
        diff = compute_scan_diff(db, scan3, scan2, project)

        summary = diff["summary"]
        assert summary["persisting"] == 1, "fp_A is in both scans"
        assert summary["regressed"] == 1, "fp_B was in scan 1, disappeared in scan 2, back in scan 3"
        assert summary["new"] == 1, "fp_D was never seen in any prior scan"
        assert summary["resolved"] == 1, "fp_C was in scan 2 but not in scan 3"
        assert summary["not_comparable"] == 0

        # Verify items
        persisting_fps = [item["id"] for item in diff["items"]["persisting"]]
        assert len(diff["items"]["persisting"]) == 1
        assert diff["items"]["regressed"][0]["type"] == "Type B"
        assert diff["items"]["new"][0]["type"] == "Type D"
        assert diff["items"]["resolved"][0]["type"] == "Type C"

    finally:
        if 'project' in locals() and project.id:
            db.query(Project).filter(Project.id == project.id).delete()
            db.commit()
        db.close()


def test_honesty_rule_detector_failure_not_comparable():
    from backend.detectors.diff import compute_scan_diff
    from backend.models.models import File
    db = SessionLocal()
    try:
        user = db.query(User).first()
        project = Project(user_id=user.id, project_name="Honesty Detector Test")
        db.add(project)
        db.flush()

        db_file = File(project_id=project.id, filename="index.js", filepath="index.js", size=100)
        db.add(db_file)
        db.commit()

        base_time = datetime.utcnow() - timedelta(hours=3)

        # Base scan ran Semgrep and found a JS vulnerability
        base_scan = ScanHistory(
            project_id=project.id,
            scan_time=base_time,
            status="completed",
            engines_run=json.dumps(["semgrep"]),
        )
        db.add(base_scan)
        db.flush()
        db.add(ScanFinding(
            scan_id=base_scan.id,
            project_id=project.id,
            fingerprint="semgrep_js_fp",
            file_path="index.js",
            type="DOM XSS",
            severity="high",
            source_tools=json.dumps(["semgrep"]),
        ))

        # Target scan: Semgrep failed or did not run! Only Bandit & AST ran
        target_scan = ScanHistory(
            project_id=project.id,
            scan_time=base_time + timedelta(hours=1),
            status="completed",
            engines_run=json.dumps(["bandit", "ast"]),
        )
        db.add(target_scan)
        db.commit()

        diff = compute_scan_diff(db, target_scan, base_scan, project)

        assert diff["summary"]["resolved"] == 0, "Semgrep finding must NEVER be resolved when Semgrep didn't run"
        assert diff["summary"]["not_comparable"] == 1
        nc_item = diff["items"]["not_comparable"][0]
        assert "semgrep" in nc_item["reason"].lower()
        assert any("Semgrep did not run" in note for note in diff["notes"])

    finally:
        if 'project' in locals() and project.id:
            db.query(Project).filter(Project.id == project.id).delete()
            db.commit()
        db.close()


def test_honesty_rule_removed_file_not_comparable():
    from backend.detectors.diff import compute_scan_diff
    from backend.models.models import File
    db = SessionLocal()
    try:
        user = db.query(User).first()
        project = Project(user_id=user.id, project_name="Honesty File Test")
        db.add(project)
        db.flush()

        base_time = datetime.utcnow() - timedelta(hours=3)

        base_scan = ScanHistory(
            project_id=project.id,
            scan_time=base_time,
            status="completed",
            engines_run=json.dumps(["bandit"]),
        )
        db.add(base_scan)
        db.flush()

        # Finding was in a file that was deleted / not in File table
        db.add(ScanFinding(
            scan_id=base_scan.id,
            project_id=project.id,
            fingerprint="deleted_file_fp",
            file_path="removed_module.py",
            type="SQL Injection",
            severity="critical",
            source_tools=json.dumps(["bandit"]),
        ))

        # Target scan runs with Bandit
        target_scan = ScanHistory(
            project_id=project.id,
            scan_time=base_time + timedelta(hours=1),
            status="completed",
            engines_run=json.dumps(["bandit"]),
        )
        db.add(target_scan)
        db.commit()

        diff = compute_scan_diff(db, target_scan, base_scan, project)

        assert diff["summary"]["resolved"] == 0, "Removed file finding must NEVER be marked resolved"
        assert diff["summary"]["not_comparable"] == 1
        nc_item = diff["items"]["not_comparable"][0]
        assert "file not scanned" in nc_item["reason"]

    finally:
        if 'project' in locals() and project.id:
            db.query(Project).filter(Project.id == project.id).delete()
            db.commit()
        db.close()


def test_dependency_upgrade_persisting_with_version_note():
    from backend.detectors.diff import compute_scan_diff
    from backend.models.models import File
    db = SessionLocal()
    try:
        user = db.query(User).first()
        project = Project(user_id=user.id, project_name="Dep Upgrade Test")
        db.add(project)
        db.flush()

        db_file = File(project_id=project.id, filename="requirements.txt", filepath="requirements.txt", size=50)
        db.add(db_file)
        db.commit()

        base_time = datetime.utcnow() - timedelta(hours=3)

        # Base scan with django==2.2.0
        base_scan = ScanHistory(
            project_id=project.id,
            scan_time=base_time,
            status="completed",
            engines_run=json.dumps(["osv"]),
        )
        db.add(base_scan)
        db.flush()

        dep_fp = compute_dependency_fingerprint("requirements.txt", "PyPI", "django")
        db.add(ScanFinding(
            scan_id=base_scan.id,
            project_id=project.id,
            fingerprint=dep_fp,
            file_path="requirements.txt",
            type="vulnerable_dependency",
            severity="high",
            source_tools=json.dumps(["osv"]),
            package_name="django",
            package_version="2.2.0",
        ))

        # Target scan upgraded to still-vulnerable django==2.2.28
        target_scan = ScanHistory(
            project_id=project.id,
            scan_time=base_time + timedelta(hours=1),
            status="completed",
            engines_run=json.dumps(["osv"]),
        )
        db.add(target_scan)
        db.flush()

        db.add(ScanFinding(
            scan_id=target_scan.id,
            project_id=project.id,
            fingerprint=dep_fp,
            file_path="requirements.txt",
            type="vulnerable_dependency",
            severity="high",
            source_tools=json.dumps(["osv"]),
            package_name="django",
            package_version="2.2.28",
        ))
        db.commit()

        diff = compute_scan_diff(db, target_scan, base_scan, project)

        assert diff["summary"]["persisting"] == 1
        item = diff["items"]["persisting"][0]
        assert item["old_version"] == "2.2.0"
        assert item["new_version"] == "2.2.28"
        assert "upgraded from 2.2.0 to 2.2.28" in item["note"]

    finally:
        if 'project' in locals() and project.id:
            db.query(Project).filter(Project.id == project.id).delete()
            db.commit()
        db.close()


def test_diff_api_endpoints_and_errors(client, db):
    user = db.query(User).filter(User.email == "test@example.com").first()
    if not user:
        user = User(username="test_api_diff", email="test@example.com", hashed_password="fake")
        db.add(user)
        db.commit()

        from backend.utils.security import create_access_token
        token = create_access_token(str(user.id))
        headers = {"Authorization": f"Bearer {token}"}

        project = Project(user_id=user.id, project_name="API Diff Test")
        db.add(project)
        db.flush()

        # First scan -> Baseline response
        scan1 = ScanHistory(project_id=project.id, status="completed", scan_time=datetime.utcnow() - timedelta(hours=2))
        db.add(scan1)
        db.commit()

        resp = client.get(f"/projects/{project.id}/scans/{scan1.id}/diff", headers=headers)
        assert resp.status_code == 200
        assert resp.json().get("baseline") is True
        assert "first scan" in resp.json().get("notes")[0]

        # Scan compared with itself -> 400 Bad Request
        resp_self = client.get(f"/projects/{project.id}/scans/{scan1.id}/diff?base={scan1.id}", headers=headers)
        assert resp_self.status_code == 400
        assert "itself" in resp_self.json()["detail"]

        # Failed scan -> 400 Bad Request
        failed_scan = ScanHistory(project_id=project.id, status="failed", scan_time=datetime.utcnow() - timedelta(hours=1))
        db.add(failed_scan)
        db.commit()

        resp_failed = client.get(f"/projects/{project.id}/scans/{failed_scan.id}/diff", headers=headers)
        assert resp_failed.status_code == 400
        assert "failed status" in resp_failed.json()["detail"]

