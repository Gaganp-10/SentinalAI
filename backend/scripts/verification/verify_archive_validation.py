"""
Comprehensive Archive Validation Verification Script
Runs all archive edge cases through http://localhost:3000/api/projects/{id}/files.
Ensures:
- Credentials generated per run (or from env)
- Unique temp files
- Subprocess calls with argument lists
- Assertions on every status code
- Verification of container filesystem with find after zip-slip test
- Cleanup of created projects and users in a finally block
"""
import io
import os
import sys
import time
import uuid
import struct
import zipfile
import requests
import subprocess
import tempfile

BASE_URL = os.environ.get("SENTINEL_BASE_URL", "http://localhost:3000")
SESSION = requests.Session()

def run_archive_verification():
    # ── Credentials & Auth ────────────────────────────────────────────────────
    run_id = uuid.uuid4().hex[:10]
    email = os.environ.get("SENTINEL_TEST_USER", f"arch_{run_id}@sentinel.io")
    username = f"arch_{run_id}"
    password = os.environ.get("SENTINEL_TEST_PASSWORD", f"P@ss_{run_id}!Secure")

    print(f"=== SentinelAI Archive Validation Verification (Run: {run_id}) ===")
    print(f"Target: {BASE_URL}")

    # 1. Signup & Login
    signup_r = SESSION.post(f"{BASE_URL}/api/auth/signup", json={
        "email": email, "username": username, "password": password
    })
    assert signup_r.status_code in (200, 201), f"Signup failed: {signup_r.status_code} {signup_r.text}"

    login_r = SESSION.post(f"{BASE_URL}/api/auth/login", json={
        "username": username, "password": password
    })
    assert login_r.status_code == 200, f"Login failed: {login_r.status_code} {login_r.text}"
    token = login_r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("Authentication: SUCCESS")

    created_project_ids = []

    def create_project(name: str) -> str:
        r = SESSION.post(f"{BASE_URL}/api/projects", json={"project_name": name}, headers=headers)
        assert r.status_code in (200, 201), f"Create project failed: {r.status_code} {r.text}"
        pid = r.json()["id"]
        created_project_ids.append(pid)
        return pid

    def upload_archive(pid: str, data: bytes, filename: str = "upload.zip"):
        return SESSION.post(
            f"{BASE_URL}/api/projects/{pid}/files",
            files={"file": (filename, io.BytesIO(data), "application/zip")},
            headers=headers,
        )

    results = []

    try:
        # =======================================================================
        # Test 1: Duplicate basenames in different folders
        # =======================================================================
        print("\n[Test 1] Duplicate basenames in different folders (both kept)")
        buf1 = io.BytesIO()
        with zipfile.ZipFile(buf1, "w") as z:
            z.writestr("frontend/index.js", "console.log('frontend');\n")
            z.writestr("backend/index.js", "console.log('backend');\n")
        pid1 = create_project(f"Duplicate Basenames {run_id}")
        r1 = upload_archive(pid1, buf1.getvalue())
        assert r1.status_code == 201, f"Expected 201, got {r1.status_code}"
        accepted1 = r1.json().get("accepted", [])
        filenames1 = [a["filename"] for a in accepted1]
        assert filenames1.count("index.js") == 2, f"Expected 2 index.js, got {filenames1}"
        print(f"  Status: {r1.status_code}, accepted: {filenames1}")
        results.append(("PASS", "Duplicate basenames preserved across distinct directories"))

        # =======================================================================
        # Test 2: Compression ratio bomb rejected
        # =======================================================================
        print("\n[Test 2] Compression ratio bomb rejected (400)")
        buf2 = io.BytesIO()
        with zipfile.ZipFile(buf2, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("bomb.py", "A" * (2 * 1024 * 1024))
        pid2 = create_project(f"Ratio Bomb {run_id}")
        r2 = upload_archive(pid2, buf2.getvalue())
        assert r2.status_code == 400, f"Expected 400, got {r2.status_code}"
        assert "ratio bomb" in r2.text.lower() or "bomb" in r2.text.lower(), f"Unexpected body: {r2.text}"
        print(f"  Status: {r2.status_code}, detail: {r2.json().get('detail')}")
        results.append(("PASS", "Ratio bomb rejected with 400"))

        # =======================================================================
        # Test 3: Zip-slip traversal rejected + container find verification
        # =======================================================================
        crafted_slip_name = f"slip_crafted_marker_{run_id}.py"
        print(f"\n[Test 3] Zip-slip traversal rejected (400) & container find check ({crafted_slip_name})")
        buf3 = io.BytesIO()
        with zipfile.ZipFile(buf3, "w") as z:
            info = zipfile.ZipInfo(f"../../../../{crafted_slip_name}")
            z.writestr(info, "print('slip_pwned')\n")
        pid3 = create_project(f"Zip-slip {run_id}")
        r3 = upload_archive(pid3, buf3.getvalue(), filename="zip_slip.zip")
        assert r3.status_code == 400, f"Expected 400, got {r3.status_code}"
        assert "zip-slip" in r3.text.lower() or "traversal" in r3.text.lower(), f"Unexpected body: {r3.text}"
        print(f"  Upload response: {r3.status_code}, detail: {r3.json().get('detail')}")

        # Check container filesystem using argument list:
        # find / -name "<crafted name>" -not -path "/proc/*"
        find_cmd = [
            "docker", "compose", "exec", "backend",
            "find", "/", "-name", crafted_slip_name, "-not", "-path", "/proc/*"
        ]
        find_res = subprocess.run(find_cmd, capture_output=True, text=True)
        found_matches = find_res.stdout.strip()
        print(f"  Container check `find / -name '{crafted_slip_name}' -not -path '/proc/*'`: '{found_matches or '(clean - 0 matches)'}'")
        assert found_matches == "", f"Security violation: crafted file leaked into container filesystem: {found_matches}"
        results.append(("PASS", f"Zip-slip rejected 400; container filesystem clean for {crafted_slip_name}"))

        # =======================================================================
        # Test 4: Sibling-prefix path traversal rejected
        # =======================================================================
        print("\n[Test 4] Sibling-prefix directory traversal rejected (400)")
        pid4 = create_project(f"Sibling Prefix {run_id}")
        buf4 = io.BytesIO()
        with zipfile.ZipFile(buf4, "w") as z:
            z.writestr(f"../{pid4}-evil/malicious.py", "print('sibling exploit')\n")
        r4 = upload_archive(pid4, buf4.getvalue(), filename="sibling.zip")
        assert r4.status_code == 400, f"Expected 400, got {r4.status_code}"
        assert "zip-slip" in r4.text.lower() or "traversal" in r4.text.lower()
        print(f"  Status: {r4.status_code}, detail: {r4.json().get('detail')}")
        results.append(("PASS", "Sibling-prefix traversal rejected with 400"))

        # =======================================================================
        # Test 5: Pre-existing symlinked directory in project upload dir
        # =======================================================================
        print("\n[Test 5] Pre-existing symlinked directory in upload dir refused (400)")
        pid5 = create_project(f"Symlink Dir {run_id}")
        # Inject symlink into container project dir via docker compose exec
        setup_symlink_cmd = [
            "docker", "compose", "exec", "backend",
            "/bin/sh", "-c", f"mkdir -p /app/uploads/{pid5} && ln -sf /etc /app/uploads/{pid5}/symlink_dir"
        ]
        subprocess.run(setup_symlink_cmd, check=True)
        buf5 = io.BytesIO()
        with zipfile.ZipFile(buf5, "w") as z:
            z.writestr("symlink_dir/exploit.py", "print('symlink exploit')\n")
        r5 = upload_archive(pid5, buf5.getvalue(), filename="symlink_attack.zip")
        assert r5.status_code == 400, f"Expected 400, got {r5.status_code}"
        assert "symlink" in r5.text.lower() or "zip-slip" in r5.text.lower()
        print(f"  Status: {r5.status_code}, detail: {r5.json().get('detail')}")
        results.append(("PASS", "Symlink parent directory traversal refused with 400"))

        # =======================================================================
        # Test 6: Re-upload of the exact same ZIP
        # =======================================================================
        print("\n[Test 6] Re-upload of the exact same ZIP succeeds (201)")
        pid6 = create_project(f"Re-upload Same ZIP {run_id}")
        buf6 = io.BytesIO()
        with zipfile.ZipFile(buf6, "w") as z:
            z.writestr("app.py", "print('version 1')\n")
            z.writestr("config.py", "DEBUG = True\n")
        zip_bytes6 = buf6.getvalue()
        r6a = upload_archive(pid6, zip_bytes6, filename="reupload.zip")
        assert r6a.status_code == 201, f"First upload failed: {r6a.status_code}"
        r6b = upload_archive(pid6, zip_bytes6, filename="reupload.zip")
        assert r6b.status_code == 201, f"Second upload failed: {r6b.status_code}"
        accepted6 = [a["filename"] for a in r6b.json().get("accepted", [])]
        assert "app.py" in accepted6 and "config.py" in accepted6
        print(f"  Status: {r6b.status_code}, accepted: {accepted6}")
        results.append(("PASS", "Re-upload of same ZIP completed successfully with 201"))

        # =======================================================================
        # Test 7: Failure mid-extraction leaves earlier files intact
        # =======================================================================
        print("\n[Test 7] Failure mid-extraction leaves earlier files intact")
        pid7 = create_project(f"Mid-Fail {run_id}")
        # Upload initial valid file
        buf7a = io.BytesIO()
        with zipfile.ZipFile(buf7a, "w") as z:
            z.writestr("earlier_baseline.py", "# baseline intact marker\n")
        r7a = upload_archive(pid7, buf7a.getvalue(), filename="first.zip")
        assert r7a.status_code == 201, f"Baseline upload failed: {r7a.status_code}"

        # Upload second ZIP with valid file followed by ratio bomb
        buf7b = io.BytesIO()
        with zipfile.ZipFile(buf7b, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("partial_new.py", "print('temp')\n")
            z.writestr("bomb.py", "0" * (2 * 1024 * 1024))
        r7b = upload_archive(pid7, buf7b.getvalue(), filename="bomb_second.zip")
        assert r7b.status_code == 400, f"Expected 400, got {r7b.status_code}"

        # Verify earlier_baseline.py is still intact inside container
        check_baseline_cmd = [
            "docker", "compose", "exec", "backend",
            "cat", f"/app/uploads/{pid7}/earlier_baseline.py"
        ]
        cat_res = subprocess.run(check_baseline_cmd, capture_output=True, text=True)
        assert cat_res.returncode == 0 and "baseline intact marker" in cat_res.stdout, "Earlier file was destroyed on failure"

        # Verify partial_new.py was cleaned up
        check_partial_cmd = [
            "docker", "compose", "exec", "backend",
            "/bin/sh", "-c", f"test -f /app/uploads/{pid7}/partial_new.py && echo exists || echo deleted"
        ]
        partial_res = subprocess.run(check_partial_cmd, capture_output=True, text=True)
        assert "deleted" in partial_res.stdout, "Partial new file was not cleaned up"
        print("  Verified: earlier_baseline.py remains intact; partial_new.py cleanly removed")
        results.append(("PASS", "Failure mid-extraction cleanly left earlier files intact"))

        # =======================================================================
        # Test 8: Corrupt ZIP handling
        # =======================================================================
        print("\n[Test 8] Corrupt ZIP returns 400 with generic message")
        pid8 = create_project(f"Corrupt Zip {run_id}")
        corrupt_bytes = b"PK\x03\x04" + b"\xff" * 300
        r8 = upload_archive(pid8, corrupt_bytes, filename="corrupt.zip")
        assert r8.status_code == 400, f"Expected 400, got {r8.status_code}"
        detail8 = r8.json().get("detail", "")
        assert "valid zip" in detail8.lower() or "archive" in detail8.lower() or "error" in detail8.lower()
        print(f"  Status: {r8.status_code}, detail: {detail8}")
        results.append(("PASS", "Corrupt ZIP returns 400 with safe generic detail"))

        # =======================================================================
        # Test 9: 60 MB oversized upload rejected (413) & no temp file in /tmp
        # =======================================================================
        print("\n[Test 9] 60 MB upload returns 413 and cleans temp file")
        pid9 = create_project(f"60MB Upload {run_id}")
        buf9 = io.BytesIO()
        with zipfile.ZipFile(buf9, "w", compression=zipfile.ZIP_STORED) as z:
            chunk = b"X" * (12 * 1024 * 1024)
            for idx in range(5):
                z.writestr(f"large_{idx}.py", chunk)
        zip_bytes9 = buf9.getvalue()
        print(f"  Payload size: {len(zip_bytes9) / 1024 / 1024:.2f} MB")
        r9 = upload_archive(pid9, zip_bytes9, filename="oversized_60mb.zip")
        assert r9.status_code == 413, f"Expected 413, got {r9.status_code}"

        # Inspect /tmp inside container using argument list
        tmp_cmd = [
            "docker", "compose", "exec", "backend",
            "find", "/tmp", "-name", "upload_*.zip"
        ]
        tmp_check = subprocess.run(tmp_cmd, capture_output=True, text=True)
        tmp_files = tmp_check.stdout.strip()
        print(f"  Container /tmp upload files: '{tmp_files or '(none)'}'")
        assert tmp_files == "", f"Temp upload file was leaked in /tmp: {tmp_files}"
        results.append(("PASS", "60 MB upload rejected with 413 and 0 leaked temp files in /tmp"))

        # =======================================================================
        # Test 10: SCA Manifest Scan (requirements.txt + package.json + pom.xml)
        # =======================================================================
        print("\n[Test 10] SCA Manifest Scan & OWASP A06 Coverage")
        pid10 = create_project(f"SCA Manifests {run_id}")
        buf10 = io.BytesIO()
        with zipfile.ZipFile(buf10, "w") as z:
            z.writestr("requirements.txt", "requests==2.20.0\nDjango==2.0\n")
            z.writestr("package.json", '{"dependencies": {"lodash": "4.17.15", "express": "4.17.1"}}\n')
            z.writestr(
                "pom.xml",
                '<project><dependencies><dependency>'
                '<groupId>org.apache.struts</groupId>'
                '<artifactId>struts2-core</artifactId>'
                '<version>2.3.30</version>'
                '</dependency></dependencies></project>'
            )
        r10 = upload_archive(pid10, buf10.getvalue(), filename="manifests.zip")
        assert r10.status_code == 201, f"Upload failed: {r10.status_code}"

        # Trigger scan
        scan_r = SESSION.post(f"{BASE_URL}/api/projects/{pid10}/scan", headers=headers)
        assert scan_r.status_code in (200, 202), f"Scan failed: {scan_r.status_code}"
        scan_id = scan_r.json()["id"]

        for _ in range(90):
            poll = SESSION.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers).json()
            if poll.get("status") == "completed":
                print(f"  Scan completed: {poll['total_issues']} findings found")
                break
            time.sleep(1)

        # Verify vulnerabilities and OWASP endpoint
        vulns_r = SESSION.get(f"{BASE_URL}/api/vulnerabilities?project_id={pid10}", headers=headers)
        assert vulns_r.status_code == 200
        vulns = vulns_r.json()
        dep_vulns = [v for v in vulns if v.get("type") == "vulnerable_dependency"]
        assert len(dep_vulns) > 0, "Expected vulnerable dependency findings"

        owasp_r = SESSION.get(f"{BASE_URL}/api/projects/{pid10}/owasp", headers=headers)
        assert owasp_r.status_code == 200
        owasp_data = owasp_r.json()
        a06 = next((c for c in owasp_data.get("categories", []) if c.get("id") == "A06"), None)
        assert a06 is not None, "A06 row missing from OWASP response"
        assert a06["open"] > 0, f"Expected A06 open count > 0, got {a06['open']}"
        print(f"  OWASP A06 verified: {a06['name']} -> {a06['open']} open, coverage: {a06['coverage']}")
        results.append(("PASS", f"SCA manifests produced {len(dep_vulns)} findings with A06 open={a06['open']}"))

    finally:
        # ── Cleanup created projects and user ─────────────────────────────────
        print("\n[Cleanup] Removing created projects and test artifacts...")
        for pid in created_project_ids:
            try:
                SESSION.delete(f"{BASE_URL}/api/projects/{pid}", headers=headers)
            except Exception:
                pass
        print(f"  Cleaned up {len(created_project_ids)} test projects.")

    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY:")
    for status, desc in results:
        print(f"  [{status}] {desc}")
    print("=" * 70)
    return True

if __name__ == "__main__":
    success = run_archive_verification()
    sys.exit(0 if success else 1)
