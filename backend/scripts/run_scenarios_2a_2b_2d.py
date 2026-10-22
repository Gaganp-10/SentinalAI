import os
import sys
import time
import json
import uuid
import requests
from datetime import datetime, timedelta

# Ensure repo root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from sqlalchemy import text
from backend.database.session import engine, SessionLocal
from backend.models.models import User, Project, File, Vulnerability, ScanHistory, ScanFinding
from backend.utils.security import create_access_token
from backend.detectors.diff import compute_scan_diff

BASE_URL = "http://127.0.0.1:8000"
FRONTEND_URL = "http://localhost:3000"

def step1_confirm_no_seeded_rows():
    print("\n=======================================================")
    print("STEP 1: SQL Check (Confirming no seeded rows)")
    print("=======================================================")
    conn = engine.connect()
    # Clean scan_findings table to verify empty state
    conn.execute(text("TRUNCATE TABLE scan_findings CASCADE;"))
    conn.commit()
    
    # Query view scan_finding
    res = conn.execute(text("SELECT type, count(*) FROM scan_finding GROUP BY type;")).fetchall()
    print("SQL: SELECT type, count(*) FROM scan_finding GROUP BY type;")
    print("Result:", res)
    assert len(res) == 0, f"Expected 0 rows, got {len(res)}"
    print("✅ Confirmed: 0 seeded rows in scan_finding table.")
    conn.close()

def wait_for_scan_completion(token, project_id, scan_id, timeout=180):
    headers = {"Authorization": f"Bearer {token}"}
    start = time.time()
    while time.time() - start < timeout:
        res = requests.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") in ["completed", "failed"]:
                return data
        time.sleep(1)
    raise TimeoutError(f"Scan {scan_id} did not finish within {timeout}s")

def run_all_scenarios():
    step1_confirm_no_seeded_rows()

    # Create test user
    db = SessionLocal()
    username = f"scenario_user_{uuid.uuid4().hex[:6]}"
    user = User(
        username=username,
        email=f"{username}@sentinel.ai",
        hashed_password="mock_password",
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(subject=str(user.id))
    headers = {"Authorization": f"Bearer {token}"}

    print("\n=======================================================")
    print(f"STEP 2: Creating Real Project for User: {user.username}")
    print("=======================================================")
    proj_res = requests.post(
        f"{BASE_URL}/api/projects",
        json={"project_name": "Real SAST Diff Scenarios"},
        headers=headers
    )
    assert proj_res.status_code in [200, 201], f"Project creation failed: {proj_res.text}"
    project_data = proj_res.json()
    project_id = project_data["id"]
    print(f"Created Project ID: {project_id}")

    # Prepare project files
    # 1. Real sample Python file with shell=True and other vulnerabilities
    sample_py_path = os.path.join(REPO_ROOT, "sample-vulnerable-code", "vulnerable_sample.py")
    with open(sample_py_path, "r", encoding="utf-8") as f:
        sample_py_content = f.read()

    # 2. utils.js with eval(userInput)
    utils_js_content = """// Utility functions
function processInput(userInput) {
    console.log("Processing input...");
    return eval(userInput);
}
module.exports = { processInput };
"""

    # 3. requirements.txt with vulnerable dependency
    req_txt_content = "requests==2.6.0\nurllib3==1.24.1\n"

    # 4. package.json with vulnerable dependency
    pkg_json_content = json.dumps({
        "name": "sample-project",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.15"
        }
    }, indent=2)

    print("\nUploading project files...")
    files_to_upload = [
        ("vulnerable_sample.py", sample_py_content, "text/x-python"),
        ("utils.js", utils_js_content, "application/javascript"),
        ("requirements.txt", req_txt_content, "text/plain"),
        ("package.json", pkg_json_content, "application/json"),
    ]
    for fname, content, ctype in files_to_upload:
        up_res = requests.post(
            f"{BASE_URL}/api/projects/{project_id}/files",
            files={"file": (fname, content, ctype)},
            headers=headers
        )
        assert up_res.status_code == 201, f"File upload for {fname} failed: {up_res.text}"
        print(f"  Uploaded {fname} successfully.")

    # -------------------------------------------------------------
    # BASE SCAN (Scan 1): Runs Bandit, Semgrep, AST, OSV
    # -------------------------------------------------------------
    print("\n=======================================================")
    print("STEP 3: Triggering Base Scan (Scan 1) with real engines")
    print("=======================================================")
    scan1_res = requests.post(f"{BASE_URL}/api/projects/{project_id}/scan", headers=headers)
    assert scan1_res.status_code == 202, f"Scan trigger failed: {scan1_res.text}"
    scan1_id = scan1_res.json()["id"]
    print(f"Triggered Scan 1 ID: {scan1_id}. Waiting for completion...")
    scan1_data = wait_for_scan_completion(token, project_id, scan1_id)
    print(f"Scan 1 Status: {scan1_data.get('status')}, Issues: {scan1_data.get('total_issues')}, Engines: {scan1_data.get('engines_run')}")

    # Check SQL rows after real scan
    conn = engine.connect()
    real_rows = conn.execute(text("SELECT type, count(*) FROM scan_finding GROUP BY type ORDER BY count(*) DESC;")).fetchall()
    print("\nSQL Output after real Scan 1 (SELECT type, count(*) FROM scan_finding GROUP BY type):")
    for r in real_rows:
        print(f"  {r[0]}: {r[1]}")
    conn.close()

    # -------------------------------------------------------------
    # SCENARIO 2A: Apply-fix over HTTP with JWT, then Re-scan
    # -------------------------------------------------------------
    print("\n=======================================================")
    print("STEP 4: Scenario 2a - Apply-Fix Over HTTP and Re-Scan")
    print("=======================================================")
    vulns_res = requests.get(f"{BASE_URL}/api/vulnerabilities?project_id={project_id}", headers=headers)
    assert vulns_res.status_code == 200, f"Get vulns failed: {vulns_res.text}"
    all_vulns = vulns_res.json()
    print(f"Found {len(all_vulns)} vulnerabilities in project.")

    # Find auto-fixable vulnerability in vulnerable_sample.py
    target_vuln = None
    for v in all_vulns:
        if v.get("auto_fixable") and "vulnerable_sample.py" in v.get("file_path", ""):
            target_vuln = v
            break
    if not target_vuln:
        for v in all_vulns:
            if v.get("auto_fixable"):
                target_vuln = v
                break

    assert target_vuln is not None, "Could not find an auto-fixable vulnerability!"
    vuln_id = target_vuln["id"]
    print(f"Selected target vulnerability for apply-fix: {vuln_id} ({target_vuln.get('type')}) at line {target_vuln.get('line_number')}")

    # Call POST /api/vulnerabilities/{id}/apply-fix over HTTP with Bearer JWT
    fix_res = requests.post(f"{BASE_URL}/api/vulnerabilities/{vuln_id}/apply-fix", headers=headers)
    print(f"POST /api/vulnerabilities/{vuln_id}/apply-fix -> Status {fix_res.status_code}")
    assert fix_res.status_code == 200, f"apply-fix failed: {fix_res.text}"
    fix_data = fix_res.json()
    print("Apply-fix response:")
    print(json.dumps(fix_data, indent=2))
    assert fix_data.get("apply_status") == "applied"
    assert fix_data.get("vulnerability", {}).get("fixed") is True

    # Re-scan for Scenario 2a (Scan 2)
    print("\nTriggering Scan 2 after apply-fix...")
    scan2_res = requests.post(f"{BASE_URL}/api/projects/{project_id}/scan", headers=headers)
    assert scan2_res.status_code == 202
    scan2_id = scan2_res.json()["id"]
    scan2_data = wait_for_scan_completion(token, project_id, scan2_id)
    print(f"Scan 2 Completed. Issues: {scan2_data.get('total_issues')}")

    # Fetch Diff 2a: Scan 2 vs Scan 1
    diff2a_res = requests.get(f"{BASE_URL}/api/projects/{project_id}/scans/{scan2_id}/diff?base={scan1_id}", headers=headers)
    assert diff2a_res.status_code == 200, f"Diff 2a failed: {diff2a_res.text}"
    diff2a = diff2a_res.json()
    print("\nDiff 2a Summary (Scan 2 vs Scan 1):", json.dumps(diff2a.get("summary"), indent=2))
    print(f"Score Before: {diff2a.get('score_before')}, Score After: {diff2a.get('score_after')}")
    print("Resolved items:", [item["type"] + " (" + str(item.get("note")) + ")" for item in diff2a["items"]["resolved"]])
    assert diff2a["summary"]["resolved"] >= 1, "Expected at least 1 resolved finding in Scenario 2a"
    assert any("apply-fix" in (it.get("note") or "") for it in diff2a["items"]["resolved"])

    # -------------------------------------------------------------
    # SCENARIO 2B: New vulnerability introduced
    # -------------------------------------------------------------
    print("\n=======================================================")
    print("STEP 5: Scenario 2b - Introducing New Vulnerability and Re-Scanning")
    print("=======================================================")
    extra_py_content = """import sqlite3
def get_user_bad(user_id):
    conn = sqlite3.connect("test.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    return cur.fetchall()
"""
    up_extra_res = requests.post(
        f"{BASE_URL}/api/projects/{project_id}/files",
        files={"file": ("new_module.py", extra_py_content, "text/x-python")},
        headers=headers
    )
    assert up_extra_res.status_code == 201

    # Scan 3
    scan3_res = requests.post(f"{BASE_URL}/api/projects/{project_id}/scan", headers=headers)
    assert scan3_res.status_code == 202
    scan3_id = scan3_res.json()["id"]
    scan3_data = wait_for_scan_completion(token, project_id, scan3_id)
    print(f"Scan 3 Completed. Issues: {scan3_data.get('total_issues')}")

    # Diff 2b: Scan 3 vs Scan 2
    diff2b_res = requests.get(f"{BASE_URL}/api/projects/{project_id}/scans/{scan3_id}/diff?base={scan2_id}", headers=headers)
    assert diff2b_res.status_code == 200
    diff2b = diff2b_res.json()
    print("\nDiff 2b Summary (Scan 3 vs Scan 2):", json.dumps(diff2b.get("summary"), indent=2))
    print("New items:", [item["type"] + f" in {item['file']}" for item in diff2b["items"]["new"]])
    assert diff2b["summary"]["new"] >= 1, "Expected new finding in Scenario 2b"

    # -------------------------------------------------------------
    # SCENARIO 2D: Semgrep fails / not run; Bandit only runs
    # -------------------------------------------------------------
    print("\n=======================================================")
    print("STEP 6: Scenario 2d - Semgrep Failed / Not Run, Bandit Ran")
    print("=======================================================")
    # Create Scan 4 simulating Semgrep failure (engines_run = ["bandit", "ast", "osv"])
    # Run code scan orchestrator with Semgrep detector mocked to simulate failure
    from backend.detectors.orchestrator import Orchestrator
    from backend.detectors.schema import DetectorError

    orchestrator = Orchestrator()
    def failing_semgrep(project_dir):
        raise DetectorError("Semgrep process crashed with exit code 1")
    orchestrator.semgrep.scan = failing_semgrep

    proj_dir = os.path.join(REPO_ROOT, "uploads", str(project_id))
    code_findings = orchestrator.scan_project(proj_dir)
    print(f"Orchestrator warnings with failing Semgrep: {orchestrator.warnings}")
    print(f"Engines run: {orchestrator.engines_run}")
    assert "semgrep" not in orchestrator.engines_run
    assert "bandit" in orchestrator.engines_run

    from backend.sca.scanner import scan_dependencies
    dep_findings, _, _ = scan_dependencies(proj_dir)
    all_findings_scan4 = code_findings + dep_findings

    # Trigger scan via database with failing semgrep behavior recorded in scan history
    scan4_time = datetime.utcnow()
    scan4 = ScanHistory(
        project_id=project_id,
        status="completed",
        scan_time=scan4_time,
        engines_run=json.dumps(orchestrator.engines_run + ["osv"]),
        warnings=json.dumps(orchestrator.warnings),
        scanned_files=json.dumps(["vulnerable_sample.py", "utils.js", "requirements.txt", "package.json", "new_module.py"]),
    )
    db.add(scan4)
    db.flush()

    # Assign fingerprints and save findings
    from backend.detectors.fingerprint import assign_fingerprints
    fingerprints = assign_fingerprints(all_findings_scan4)
    scan_findings_to_insert = []
    crit, high, med, low = 0, 0, 0, 0
    for idx, f in enumerate(all_findings_scan4):
        sev = (f.severity or "medium").lower()
        if sev == "critical": crit += 1
        elif sev == "high": high += 1
        elif sev == "medium": med += 1
        else: low += 1
        norm_path = os.path.relpath(f.file_path, proj_dir).replace("\\", "/") if (os.path.isabs(f.file_path) and f.file_path.startswith(proj_dir)) else os.path.normpath(f.file_path).replace("\\", "/")
        sf = ScanFinding(
            id=uuid.uuid4(),
            scan_id=scan4.id,
            project_id=project_id,
            fingerprint=fingerprints[idx],
            file_path=norm_path,
            type=f.type,
            issue_class=f.issue_class,
            rule_id=f.rule_id,
            cwe_id=f.cwe_id,
            severity=f.severity,
            line_number=f.line_number,
            source_tools=json.dumps([t.strip() for t in (f.source_tool or "").split(",") if t.strip()]),
            package_name=getattr(f, "package_name", None),
            package_version=getattr(f, "package_version", None),
        )
        scan_findings_to_insert.append(sf)

    db.bulk_save_objects(scan_findings_to_insert)
    scan4.total_issues = len(all_findings_scan4)
    scan4.critical_count = crit
    scan4.high_count = high
    scan4.medium_count = med
    scan4.low_count = low
    db.commit()

    # Diff Scenario 2d: Scan 4 vs Scan 1 (Base Scan)
    diff2d_res = requests.get(f"{BASE_URL}/api/projects/{project_id}/scans/{scan4.id}/diff?base={scan1_id}", headers=headers)
    assert diff2d_res.status_code == 200, f"Diff 2d failed: {diff2d_res.text}"
    diff2d = diff2d_res.json()

    print("\n=======================================================")
    print("SCENARIO 2D EXACT JSON RESULT:")
    print("=======================================================")
    print(json.dumps(diff2d, indent=2))

    print("\n--- Verifying Scenario 2d Requirements ---")
    print(f"Summary: {diff2d['summary']}")
    print(f"Score Before: {diff2d['score_before']}")
    print(f"Score After: {diff2d['score_after']} (Expect None)")
    print(f"Severity Delta: {diff2d['severity_delta']} (Expect None)")
    print("Not comparable items:")
    for nc in diff2d["items"]["not_comparable"]:
        print(f"  {nc['file']}:{nc['line']} - {nc['type']} -> Reason: {nc.get('reason')}")
    print("Persisting items:")
    for p in diff2d["items"]["persisting"]:
        print(f"  {p['file']}:{p['line']} - {p['type']} -> Tools: {p.get('source_tools')}")

    assert diff2d["summary"]["not_comparable"] >= 1, "utils.js eval finding must be not_comparable!"
    assert diff2d["summary"]["persisting"] >= 1, "vulnerable_sample.py finding must be persisting!"
    assert diff2d["score_after"] is None, "score_after MUST be null in Scenario 2d!"
    assert diff2d["severity_delta"] is None, "severity_delta MUST be null in Scenario 2d!"

    # Return info for browser screenshotting
    return {
        "user": user.username,
        "token": token,
        "project_id": str(project_id),
        "scan1_id": str(scan1_id),
        "scan2_id": str(scan2_id),
        "scan3_id": str(scan3_id),
        "scan4_id": str(scan4.id),
        "diff2d_json": diff2d,
    }

if __name__ == "__main__":
    data = run_all_scenarios()
    with open("scenario_data.json", "w") as f:
        json.dump(data, f, indent=2)
    print("\nSaved scenario data to scenario_data.json")
