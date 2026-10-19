import os
import sys
import tempfile
import json
import time
import shutil
from datetime import datetime
from uuid import uuid4

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.models.models import Base, User, Project, File, Vulnerability, ScanHistory, ScanFinding
from backend.api.scans import run_background_scan
from backend.detectors.diff import compute_scan_diff
from backend.utils.config import settings

def create_test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session, Session()

def run_step8_verifications():
    print("=" * 80)
    print("STARTING POLISH STEP 8 VERIFICATION SCENARIOS")
    print("=" * 80)

    Session, db = create_test_db()

    # Create dummy user
    user = User(
        id=uuid4(),
        username="verifier",
        email="verifier@sentinel.ai",
        hashed_password="hashed_pwd",
        is_active=True
    )
    db.add(user)
    db.commit()

    # Create project and project dir
    project_id = uuid4()
    project = Project(
        id=project_id,
        project_name="Step8 Verification Project",
        user_id=user.id
    )
    db.add(project)
    db.commit()

    project_dir = os.path.abspath(os.path.join(settings.UPLOAD_DIR, str(project_id)))
    os.makedirs(project_dir, exist_ok=True)

    def register_files():
        # Clear existing File records and re-register from project_dir
        db.query(File).filter(File.project_id == project_id).delete()
        for root, _, files in os.walk(project_dir):
            for fname in files:
                rel = os.path.relpath(os.path.join(root, fname), project_dir).replace("\\", "/")
                f_record = File(
                    id=uuid4(),
                    project_id=project_id,
                    filename=fname,
                    filepath=rel,
                    size=os.path.getsize(os.path.join(root, fname))
                )
                db.add(f_record)
        db.commit()

    import backend.api.scans as scans_module
    scans_module.SessionLocal = Session

    import backend.ai.explainer as explainer_module
    explainer_module.generate_vulnerability_explanation = lambda f: "Simulated explanation for verification"

    import backend.fixer.fix_generator as fixer_module
    fixer_module.generate_patched_code = lambda f, c: ("Simulated fix", "# Patched code", "--- +++", True, "rule_template")

    def execute_scan():
        register_files()
        scan = ScanHistory(
            id=uuid4(),
            project_id=project_id,
            status="pending",
            scan_time=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        run_background_scan(project_id, scan.id)
        db.refresh(scan)
        findings_in_db = db.query(ScanFinding).filter(ScanFinding.scan_id == scan.id).all()
        for sf in findings_in_db:
            print(f"  * {sf.file_path}:{sf.line_number} [{sf.severity}] {sf.type} (tools: {sf.source_tools})")
        return scan

    # -------------------------------------------------------------
    # SCENARIO 1: Base scan (Python sample + JS file + requirements.txt)
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SCENARIO 1: Base scan with Python sample + JS file + requirements.txt (django==2.2.0)")
    print("=" * 80)

    py_code_vuln = """import sqlite3
import subprocess
import hashlib

def run_query(user_input):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user_input)
    return cursor.fetchall()

def execute_cmd(user_cmd):
    subprocess.call(user_cmd, shell=True)

def hash_data(data):
    return hashlib.md5(data.encode()).hexdigest()
"""
    with open(os.path.join(project_dir, "app.py"), "w", encoding="utf-8") as f:
        f.write(py_code_vuln)

    js_code = """function executeCode(userInput) {
    eval(userInput);
}
"""
    with open(os.path.join(project_dir, "utils.js"), "w", encoding="utf-8") as f:
        f.write(js_code)

    req_content = "django==2.2.0\n"
    with open(os.path.join(project_dir, "requirements.txt"), "w", encoding="utf-8") as f:
        f.write(req_content)

    scan1 = execute_scan()
    print(f"Scan 1 Completed (ID: {scan1.id}): {scan1.total_issues} issues found. Engines: {scan1.engines_run}")
    
    # Check baseline diff
    from backend.api.scans import handle_scan_diff
    baseline_diff = handle_scan_diff(scan1.id, None, db, user, project_id=project_id)
    print("\nBaseline Diff Response:")
    print(json.dumps(baseline_diff, indent=2))

    # -------------------------------------------------------------
    # SCENARIO 2: Apply 2 fixes and rescan (expect resolved = 2, new = 0)
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SCENARIO 2: Apply 2 fixes in Python file and rescan")
    print("=" * 80)

    # We fix the SQL injection and command injection in app.py
    py_code_fixed = """import sqlite3
import hashlib

def run_query(user_input):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
    return cursor.fetchall()

def execute_cmd(user_cmd):
    # Subprocess call removed completely to fix command injection
    return f"Executed safely: {user_cmd}"

def hash_data(data):
    return hashlib.md5(data.encode()).hexdigest()
"""
    with open(os.path.join(project_dir, "app.py"), "w", encoding="utf-8") as f:
        f.write(py_code_fixed)

    scan2 = execute_scan()
    print(f"Scan 2 Completed (ID: {scan2.id}): {scan2.total_issues} issues found.")
    
    diff2 = handle_scan_diff(scan2.id, scan1.id, db, user, project_id=project_id)
    print("\nDiff Response (Scan 2 vs Scan 1):")
    print(json.dumps(diff2, indent=2))

    # -------------------------------------------------------------
    # SCENARIO 3: Re-introduce 1 fixed line and rescan (expect regressed = 1)
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SCENARIO 3: Re-introduce 1 fixed line (subprocess.call(shell=True)) and rescan")
    print("=" * 80)

    py_code_regressed = """import sqlite3
import subprocess
import hashlib

def run_query(user_input):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
    return cursor.fetchall()

def execute_cmd(user_cmd):
    subprocess.call(user_cmd, shell=True)

def hash_data(data):
    return hashlib.md5(data.encode()).hexdigest()
"""
    with open(os.path.join(project_dir, "app.py"), "w", encoding="utf-8") as f:
        f.write(py_code_regressed)

    scan3 = execute_scan()
    print(f"Scan 3 Completed (ID: {scan3.id}): {scan3.total_issues} issues found.")

    diff3 = handle_scan_diff(scan3.id, scan2.id, db, user, project_id=project_id)
    print("\nDiff Response (Scan 3 vs Scan 2):")
    print(json.dumps(diff3, indent=2))

    # -------------------------------------------------------------
    # SCENARIO 4: Insert 10 blank lines at top and rescan (expect persisting = all, new = 0, resolved = 0)
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SCENARIO 4: Insert 10 blank lines at top of app.py and rescan")
    print("=" * 80)

    with open(os.path.join(project_dir, "app.py"), "w", encoding="utf-8") as f:
        f.write("\n\n\n\n\n\n\n\n\n\n" + py_code_regressed)

    scan4 = execute_scan()
    print(f"Scan 4 Completed (ID: {scan4.id}): {scan4.total_issues} issues found.")

    diff4 = handle_scan_diff(scan4.id, scan3.id, db, user, project_id=project_id)
    print("\nDiff Response (Scan 4 vs Scan 3):")
    print(json.dumps(diff4, indent=2))

    # -------------------------------------------------------------
    # SCENARIO 5: Temporarily break Semgrep rules path and rescan (expect JS finding not_comparable)
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SCENARIO 5: Temporarily point Semgrep rules path to invalid path and rescan")
    print("=" * 80)

    from backend.detectors.semgrep_detector import SemgrepDetector
    from backend.detectors.schema import DetectorError

    orig_semgrep_scan = SemgrepDetector.scan
    def failing_semgrep_scan(self, project_dir):
        raise DetectorError("Semgrep scan failed: rules file not found at invalid path")
    SemgrepDetector.scan = failing_semgrep_scan

    try:
        scan5 = execute_scan()
        print(f"Scan 5 Completed (ID: {scan5.id}): {scan5.total_issues} issues found. Engines: {scan5.engines_run}")
        diff5 = handle_scan_diff(scan5.id, scan4.id, db, user, project_id=project_id)
        print("\nDiff Response (Scan 5 vs Scan 4):")
        print(json.dumps(diff5, indent=2))
    finally:
        SemgrepDetector.scan = orig_semgrep_scan

    # -------------------------------------------------------------
    # SCENARIO 6: Remove JS file from project and rescan (expect not_comparable: file not scanned)
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SCENARIO 6: Remove utils.js and rescan")
    print("=" * 80)

    js_file_path = os.path.join(project_dir, "utils.js")
    if os.path.exists(js_file_path):
        os.remove(js_file_path)

    scan6 = execute_scan()
    print(f"Scan 6 Completed (ID: {scan6.id}): {scan6.total_issues} issues found.")
    diff6 = handle_scan_diff(scan6.id, scan4.id, db, user, project_id=project_id)
    print("\nDiff Response (Scan 6 vs Scan 4):")
    print(json.dumps(diff6, indent=2))

    # -------------------------------------------------------------
    # SCENARIO 7: Upgrade dependency to another vulnerable version (django==2.2.28)
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SCENARIO 7: Upgrade django from 2.2.0 to 2.2.28 in requirements.txt")
    print("=" * 80)

    with open(os.path.join(project_dir, "requirements.txt"), "w", encoding="utf-8") as f:
        f.write("django==2.2.28\n")

    scan7 = execute_scan()
    print(f"Scan 7 Completed (ID: {scan7.id}): {scan7.total_issues} issues found.")
    diff7 = handle_scan_diff(scan7.id, scan6.id, db, user, project_id=project_id)
    print("\nDiff Response (Scan 7 vs Scan 6):")
    print(json.dumps(diff7, indent=2))

    # -------------------------------------------------------------
    # SCENARIO 8: Benchmark performance (time diff and snapshot write on large synthetic dataset)
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SCENARIO 8: Benchmark Diff & Snapshot Write (3,000 files, 3,000 findings)")
    print("=" * 80)

    from datetime import timedelta
    bench_scan_base = ScanHistory(
        id=uuid4(),
        project_id=project_id,
        status="completed",
        scan_time=datetime.utcnow() - timedelta(minutes=5),
        engines_run=json.dumps(["bandit", "ast", "semgrep", "osv"])
    )
    db.add(bench_scan_base)
    db.commit()

    # Create 3,000 findings for base
    base_findings = []
    for i in range(3000):
        bf = ScanFinding(
            id=uuid4(),
            scan_id=bench_scan_base.id,
            project_id=project_id,
            fingerprint=f"fp_benchmark_hash_{i:04d}",
            file_path=f"src/module_{i % 50}/file_{i}.py",
            type="sql_injection" if i % 2 == 0 else "command_injection",
            issue_class="sql_injection",
            severity="high" if i % 2 == 0 else "medium",
            line_number=10 + (i % 100),
            source_tools='["bandit"]'
        )
        base_findings.append(bf)

    t0 = time.time()
    db.bulk_save_objects(base_findings)
    db.commit()
    t_bulk_write = time.time() - t0
    print(f"Snapshot Bulk Write of 3,000 ScanFindings: {t_bulk_write*1000:.2f} ms")

    bench_scan_target = ScanHistory(
        id=uuid4(),
        project_id=project_id,
        status="completed",
        scan_time=datetime.utcnow(),
        engines_run=json.dumps(["bandit", "ast", "semgrep", "osv"])
    )
    db.add(bench_scan_target)
    db.commit()

    # Create 3,000 target findings:
    # 2,500 persisting (same fp), 500 new, 500 resolved
    target_findings = []
    for i in range(2500):
        tf = ScanFinding(
            id=uuid4(),
            scan_id=bench_scan_target.id,
            project_id=project_id,
            fingerprint=f"fp_benchmark_hash_{i:04d}",
            file_path=f"src/module_{i % 50}/file_{i}.py",
            type="sql_injection" if i % 2 == 0 else "command_injection",
            issue_class="sql_injection",
            severity="high" if i % 2 == 0 else "medium",
            line_number=15 + (i % 100),
            source_tools='["bandit"]'
        )
        target_findings.append(tf)

    for i in range(3000, 3500):
        tf = ScanFinding(
            id=uuid4(),
            scan_id=bench_scan_target.id,
            project_id=project_id,
            fingerprint=f"fp_benchmark_hash_new_{i:04d}",
            file_path=f"src/new_module/new_{i}.py",
            type="weak_cryptography",
            issue_class="weak_hash",
            severity="low",
            line_number=5,
            source_tools='["bandit"]'
        )
        target_findings.append(tf)

    db.bulk_save_objects(target_findings)
    db.commit()

    t0 = time.time()
    diff_bench = compute_scan_diff(db, bench_scan_target, bench_scan_base, project)
    t_diff = time.time() - t0
    print(f"Scan Diff computation for 3,000 findings: {t_diff*1000:.2f} ms")
    print(f"Benchmark Diff Summary: {json.dumps(diff_bench['summary'])}")

    # Clean up temp files
    shutil.rmtree(project_dir, ignore_errors=True)

    print("\n" + "=" * 80)
    print("ALL VERIFICATION SCENARIOS COMPLETED SUCCESSFULLY!")
    print("=" * 80)

if __name__ == "__main__":
    run_step8_verifications()
