import os
import sys
import time
import json
import shutil
from datetime import datetime, timedelta
from uuid import uuid4

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.models.models import Base, User, Project, File, ScanHistory, ScanFinding
from backend.api.scans import run_background_scan
from backend.detectors.diff import compute_scan_diff
from backend.utils.config import settings

def benchmark_real_3000_files():
    print("=" * 80)
    print("GENERATING 3,000 REAL FILES AND RUNNING SCAN + SNAPSHOT WRITE + DIFF")
    print("=" * 80)

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    user = User(
        id=uuid4(),
        username="benchmarker",
        email="benchmarker@sentinel.ai",
        hashed_password="hashed_pwd",
        is_active=True
    )
    db.add(user)
    db.commit()

    project_id = uuid4()
    project = Project(
        id=project_id,
        project_name="3000-File Real Scan Benchmark",
        user_id=user.id
    )
    db.add(project)
    db.commit()

    project_dir = os.path.abspath(os.path.join(settings.UPLOAD_DIR, str(project_id)))
    os.makedirs(project_dir, exist_ok=True)

    print(f"Creating 3,000 files in {project_dir}...")
    t_gen_start = time.time()
    files_to_db = []
    for i in range(3000):
        fname = f"module_{i:04d}.py"
        fpath = os.path.join(project_dir, fname)
        if i < 50:
            content = f'''import hashlib
def process_data_{i}(data):
    return hashlib.md5(data.encode()).hexdigest()
'''
        else:
            content = f'''def compute_{i}(val):
    return val * {i} + 1
'''
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)

        files_to_db.append(File(
            id=uuid4(),
            project_id=project_id,
            filename=fname,
            filepath=fname,
            size=len(content)
        ))

    db.bulk_save_objects(files_to_db)
    db.commit()
    t_gen = time.time() - t_gen_start
    print(f"Generated 3,000 files and registered in DB in {t_gen:.2f}s")

    import backend.api.scans as scans_module
    scans_module.SessionLocal = Session

    import backend.ai.explainer as explainer_module
    explainer_module.generate_vulnerability_explanation = lambda f: "Simulated explanation for benchmark"

    import backend.fixer.fix_generator as fixer_module
    fixer_module.generate_patched_code = lambda f, c: ("Simulated fix", "# Patched code", "--- +++", True, "rule_template")

    # SCAN 1: Real background scan of all 3,000 files
    print("\n--- Executing Real Scan 1 (3,000 files) ---")
    scan1 = ScanHistory(
        id=uuid4(),
        project_id=project_id,
        status="pending",
        scan_time=datetime.utcnow() - timedelta(minutes=10)
    )
    db.add(scan1)
    db.commit()

    t_scan1_start = time.time()
    run_background_scan(project_id, scan1.id)
    t_scan1 = time.time() - t_scan1_start
    db.refresh(scan1)

    scan1_findings = db.query(ScanFinding).filter(ScanFinding.scan_id == scan1.id).all()
    count_scan1 = len(scan1_findings)
    print(f"Scan 1 Completed: {scan1.total_issues} issues found across 3,000 files.")
    print(f"Real Scan 1 Total Time (detector execution + snapshot write): {t_scan1:.2f}s")
    print(f"ScanFinding rows written for Scan 1: {count_scan1}")

    # Now modify some files for Scan 2:
    print("\n--- Modifying files and executing Real Scan 2 (3,000 files) ---")
    for i in range(20):
        fpath = os.path.join(project_dir, f"module_{i:04d}.py")
        content = f'''import hashlib
def process_data_{i}(data):
    return hashlib.sha256(data.encode()).hexdigest()
'''
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)

    for i in range(50, 60):
        fpath = os.path.join(project_dir, f"module_{i:04d}.py")
        content = f'''import hashlib
def process_data_{i}(data):
    return hashlib.md5(data.encode()).hexdigest()
'''
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content)

    scan2 = ScanHistory(
        id=uuid4(),
        project_id=project_id,
        status="pending",
        scan_time=datetime.utcnow()
    )
    db.add(scan2)
    db.commit()

    t_scan2_start = time.time()
    run_background_scan(project_id, scan2.id)
    t_scan2 = time.time() - t_scan2_start
    db.refresh(scan2)

    scan2_findings = db.query(ScanFinding).filter(ScanFinding.scan_id == scan2.id).all()
    count_scan2 = len(scan2_findings)
    total_scan_findings = db.query(ScanFinding).filter(ScanFinding.project_id == project_id).count()

    print(f"Scan 2 Completed: {scan2.total_issues} issues found across 3,000 files.")
    print(f"Real Scan 2 Total Time: {t_scan2:.2f}s")
    print(f"ScanFinding rows written for Scan 2: {count_scan2}")
    print(f"Total ScanFinding rows in DB for this project: {total_scan_findings}")

    # Compute Diff between Scan 2 and Scan 1
    t_diff_start = time.time()
    diff_result = compute_scan_diff(db, scan2, scan1, project)
    t_diff = time.time() - t_diff_start
    print(f"\nReal Scan Diff Computation Time: {t_diff*1000:.2f} ms ({t_diff:.4f}s)")
    print(f"Diff Summary: {json.dumps(diff_result['summary'], indent=2)}")

    shutil.rmtree(project_dir, ignore_errors=True)
    print("\nBenchmark completed and clean up done.")

if __name__ == "__main__":
    benchmark_real_3000_files()
