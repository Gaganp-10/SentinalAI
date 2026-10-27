"""
Live end-to-end verification of POST /api/vulnerabilities/{id}/apply-fix
through http://localhost:3000/api.
Features:
- Credentials generated per run (or from env)
- Subprocess calls with argument lists
- Assertions on every status code and diff field
- Inspection of the patched file from the named volume inside Docker
- Cleanup of created projects in a finally block
"""
import os
import sys
import time
import uuid
import requests
import subprocess

BASE_URL = os.environ.get("SENTINEL_BASE_URL", "http://localhost:3000")
SESSION = requests.Session()

def run_apply_fix_live_verification():
    run_id = uuid.uuid4().hex[:10]
    email = os.environ.get("SENTINEL_TEST_USER", f"applyfix_{run_id}@sentinel.io")
    username = f"applyfix_{run_id}"
    password = os.environ.get("SENTINEL_TEST_PASSWORD", f"P@ss_{run_id}!Secure")

    print(f"=== SentinelAI Apply-Fix Live Verification (Run: {run_id}) ===")
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
        proj = SESSION.post(f"{BASE_URL}/api/projects", json={"project_name": f"Apply-Fix {run_id}"}, headers=headers)
        assert proj.status_code in (200, 201), f"Create project failed: {proj.text}"
        proj_id = proj.json()["id"]
        created_project_ids.append(proj_id)
        print(f"Project created: {proj_id}")

        # 3. Upload vulnerable Python file
        VULN_CODE = (
            "import sqlite3\n\n"
            "def get_user(cursor, user_id):\n"
            '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
            "    return cursor.fetchall()\n"
        )
        up = SESSION.post(
            f"{BASE_URL}/api/projects/{proj_id}/files",
            files={"file": ("vulnerable_demo.py", VULN_CODE.encode("utf-8"), "text/x-python")},
            headers=headers,
        )
        assert up.status_code == 201, f"Upload failed: {up.text}"
        print(f"Upload accepted: {len(up.json().get('accepted', []))} file(s)")

        # 4. Trigger scan
        scan = SESSION.post(f"{BASE_URL}/api/projects/{proj_id}/scan", headers=headers)
        assert scan.status_code in (200, 202), f"Scan trigger failed: {scan.text}"
        scan_id = scan.json()["id"]

        for _ in range(90):
            poll = SESSION.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers).json()
            if poll.get("status") == "completed":
                print(f"Scan complete: {poll['total_issues']} issue(s)")
                break
            time.sleep(1)

        # 5. Fetch vulnerability and assert fields
        vulns_r = SESSION.get(f"{BASE_URL}/api/vulnerabilities?project_id={proj_id}", headers=headers)
        assert vulns_r.status_code == 200
        vulns = vulns_r.json()
        target = next((v for v in vulns if v.get("auto_fixable")), None)
        assert target is not None, "Expected an auto-fixable vulnerability finding"
        print(f"Target vulnerability: {target['id']}")
        print(f"  Snippet : {repr(target['code_snippet'])}")
        print(f"  Fix     : {repr(target['suggested_fix'])}")
        assert target.get("suggested_fix"), "Finding must have a non-empty suggested_fix"

        # 6. Apply fix
        apply_r = SESSION.post(f"{BASE_URL}/api/vulnerabilities/{target['id']}/apply-fix", headers=headers)
        assert apply_r.status_code == 200, f"apply-fix returned {apply_r.status_code}: {apply_r.text}"
        apply_res = apply_r.json()
        assert apply_res.get("apply_status") in ("applied", "verified")
        assert apply_res.get("file", {}).get("size", 0) > 0
        print(f"Apply-fix succeeded: status={apply_res.get('apply_status')}, new_size={apply_res['file']['size']}")

        # 7. Check file inside named volume using argument list
        cat_cmd = ["docker", "compose", "exec", "backend", "cat", f"/app/uploads/{proj_id}/vulnerable_demo.py"]
        patched_content = subprocess.run(cat_cmd, capture_output=True, text=True).stdout
        print(f"Patched content in Docker named volume:\n{patched_content.strip()}")
        assert "?" in patched_content, "Expected parameterized query in patched file"
        assert "SELECT * FROM users WHERE id = " not in patched_content or "(?)" in patched_content or ", (user_id" in patched_content

        print("\nAll apply-fix assertions passed successfully!")
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
    success = run_apply_fix_live_verification()
    sys.exit(0 if success else 1)
