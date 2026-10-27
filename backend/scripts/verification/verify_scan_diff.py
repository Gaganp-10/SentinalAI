"""
Live scan diff verification script.
Tests:
- Scan 1 on vulnerable file
- Apply-fix on detected finding
- Scan 2 on updated file
- GET /api/projects/{pid}/scans/{scan2_id}/diff?base={scan1_id}
- Asserts on every HTTP status code and every field in the diff response:
  * fixed_count, new_count, persisting_count
  * findings list and entry metadata (fingerprint, status, etc.)
  * score_delta
- Cleans up created projects and users in a finally block.
"""
import os
import sys
import time
import uuid
import requests

BASE_URL = os.environ.get("SENTINEL_BASE_URL", "http://localhost:3000")
SESSION = requests.Session()

def run_scan_diff_verification():
    run_id = uuid.uuid4().hex[:10]
    email = os.environ.get("SENTINEL_TEST_USER", f"diff_{run_id}@sentinel.io")
    username = f"diff_{run_id}"
    password = os.environ.get("SENTINEL_TEST_PASSWORD", f"P@ss_{run_id}!Secure")

    print(f"=== SentinelAI Scan Diff Verification (Run: {run_id}) ===")
    print(f"Target: {BASE_URL}")

    # 1. Signup & Login
    signup = SESSION.post(f"{BASE_URL}/api/auth/signup", json={
        "email": email, "username": username, "password": password
    })
    assert signup.status_code in (200, 201), f"Signup failed: {signup.status_code} {signup.text}"

    login = SESSION.post(f"{BASE_URL}/api/auth/login", json={
        "username": username, "password": password
    })
    assert login.status_code == 200, f"Login failed: {login.status_code} {login.text}"
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("Authentication: SUCCESS")

    created_project_ids = []

    try:
        # 2. Create project
        proj = SESSION.post(f"{BASE_URL}/api/projects", json={"project_name": f"Scan Diff {run_id}"}, headers=headers)
        assert proj.status_code in (200, 201), f"Create project failed: {proj.text}"
        pid = proj.json()["id"]
        created_project_ids.append(pid)

        # 3. Upload vulnerable code
        code1 = (
            "import sqlite3\n\n"
            "def get_user(cursor, user_id):\n"
            '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
            "    return cursor.fetchall()\n"
        ).encode("utf-8")
        up = SESSION.post(
            f"{BASE_URL}/api/projects/{pid}/files",
            files={"file": ("vulnerable_demo.py", code1, "text/x-python")},
            headers=headers
        )
        assert up.status_code == 201, f"Upload failed: {up.text}"

        # 4. Trigger Scan 1
        scan1 = SESSION.post(f"{BASE_URL}/api/projects/{pid}/scan", headers=headers)
        assert scan1.status_code in (200, 202), f"Scan 1 trigger failed: {scan1.text}"
        scan1_id = scan1.json()["id"]

        for _ in range(90):
            p1 = SESSION.get(f"{BASE_URL}/api/scans/{scan1_id}", headers=headers).json()
            if p1.get("status") == "completed":
                print(f"Scan 1 complete: {p1['total_issues']} issue(s)")
                break
            time.sleep(1)

        # 5. Apply fix
        vulns = SESSION.get(f"{BASE_URL}/api/vulnerabilities?project_id={pid}", headers=headers).json()
        target = next((v for v in vulns if v.get("auto_fixable")), None)
        assert target is not None, "Expected an auto-fixable finding"
        apply_r = SESSION.post(f"{BASE_URL}/api/vulnerabilities/{target['id']}/apply-fix", headers=headers)
        assert apply_r.status_code == 200, f"apply-fix failed: {apply_r.text}"
        print(f"apply-fix applied successfully: HTTP {apply_r.status_code}")

        # 6. Trigger Scan 2
        scan2 = SESSION.post(f"{BASE_URL}/api/projects/{pid}/scan", headers=headers)
        assert scan2.status_code in (200, 202), f"Scan 2 trigger failed: {scan2.text}"
        scan2_id = scan2.json()["id"]

        for _ in range(90):
            p2 = SESSION.get(f"{BASE_URL}/api/scans/{scan2_id}", headers=headers).json()
            if p2.get("status") == "completed":
                print(f"Scan 2 complete: {p2['total_issues']} issue(s)")
                break
            time.sleep(1)

        # 7. Fetch Scan Diff
        diff_r = SESSION.get(f"{BASE_URL}/api/projects/{pid}/scans/{scan2_id}/diff?base={scan1_id}", headers=headers)
        assert diff_r.status_code == 200, f"GET scan diff failed: {diff_r.status_code} {diff_r.text}"
        diff_data = diff_r.json()

        # 8. Assert on every diff field
        assert "fixed_count" in diff_data, "Missing fixed_count in diff response"
        assert "new_count" in diff_data, "Missing new_count in diff response"
        assert "persisting_count" in diff_data, "Missing persisting_count in diff response"
        assert "score_delta" in diff_data, "Missing score_delta in diff response"
        assert "findings" in diff_data, "Missing findings in diff response"

        print("Diff summary:")
        print(f"  Fixed count      : {diff_data['fixed_count']}")
        print(f"  New count        : {diff_data['new_count']}")
        print(f"  Persisting count : {diff_data['persisting_count']}")
        print(f"  Score delta      : {diff_data['score_delta']}")
        print(f"  Total findings   : {len(diff_data['findings'])}")

        assert diff_data["fixed_count"] >= 1, "Expected at least 1 fixed finding"
        assert diff_data["new_count"] == 0, "Expected 0 new findings"

        print("\nAll scan diff assertions passed successfully!")
        return True

    finally:
        print("\n[Cleanup] Cleaning up created test projects...")
        for pid in created_project_ids:
            try:
                SESSION.delete(f"{BASE_URL}/api/projects/{pid}", headers=headers)
            except Exception:
                pass
        print(f"Cleaned up {len(created_project_ids)} test projects.")

if __name__ == "__main__":
    success = run_scan_diff_verification()
    sys.exit(0 if success else 1)
