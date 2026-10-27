"""
Benchmark verification script for large file-count archive upload.
Tests 3000-file ZIP upload through http://localhost:3000/api.
Features:
- Credentials generated per run (or from env)
- Memory sampling via subprocess call with argument list
- Assertions on status code and response payload
- Full cleanup of created projects in a finally block.
"""
import os
import sys
import time
import uuid
import requests
import threading
import subprocess

BASE_URL = os.environ.get("SENTINEL_BASE_URL", "http://localhost:3000")
ZIP_PATH = os.path.join("backend", "tests", "test_archives", "7_large_count_3000.zip")
SESSION = requests.Session()

def run_upload_benchmark():
    if not os.path.exists(ZIP_PATH):
        print(f"Benchmark ZIP {ZIP_PATH} not found; skipping.")
        return True

    run_id = uuid.uuid4().hex[:10]
    email = os.environ.get("SENTINEL_TEST_USER", f"bench_{run_id}@sentinel.io")
    username = f"bench_{run_id}"
    password = os.environ.get("SENTINEL_TEST_PASSWORD", f"P@ss_{run_id}!Secure")

    print(f"=== SentinelAI 3000 Files Upload Benchmark (Run: {run_id}) ===")

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

    created_project_ids = []

    try:
        proj = SESSION.post(f"{BASE_URL}/api/projects", json={"project_name": f"Benchmark 3000 {run_id}"}, headers=headers)
        assert proj.status_code in (200, 201), f"Create project failed: {proj.text}"
        proj_id = proj.json()["id"]
        created_project_ids.append(proj_id)
        print(f"Created benchmark project: {proj_id}")

        sampling = True
        mem_samples = []

        def sample_memory():
            while sampling:
                try:
                    cmd = ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", "securityvulnerabilitydecoderandfixer-backend-1"]
                    out = subprocess.check_output(cmd, text=True).strip()
                    mem_samples.append((time.time(), out))
                except Exception:
                    pass
                time.sleep(1)

        t_sampler = threading.Thread(target=sample_memory, daemon=True)
        t_sampler.start()

        print(f"Starting upload of {ZIP_PATH}...")
        t0 = time.time()
        with open(ZIP_PATH, "rb") as f:
            files = {"file": ("7_large_count_3000.zip", f, "application/zip")}
            upload_res = SESSION.post(f"{BASE_URL}/api/projects/{proj_id}/files", files=files, headers=headers)
        t1 = time.time()
        sampling = False
        t_sampler.join(timeout=2)

        print(f"Upload completed in {t1 - t0:.2f} s with HTTP status {upload_res.status_code}")
        assert upload_res.status_code == 201, f"Expected 201, got {upload_res.status_code}: {upload_res.text}"
        data = upload_res.json()
        accepted_count = len(data.get("accepted", []))
        print(f"Accepted files: {accepted_count}, Skipped: {data.get('skipped', {})}")
        assert accepted_count >= 1, "Expected accepted files in response"

        if mem_samples:
            print("Memory samples during upload:")
            for ts, mem in mem_samples[:5]:
                print(f"  {mem}")

        print("Benchmark test completed successfully!")
        return True

    finally:
        print("\n[Cleanup] Cleaning up created test projects...")
        for pid in created_project_ids:
            try:
                SESSION.delete(f"{BASE_URL}/api/projects/{pid}", headers=headers)
            except Exception:
                pass
        print(f"Cleaned up {len(created_project_ids)} benchmark projects.")

if __name__ == "__main__":
    success = run_upload_benchmark()
    sys.exit(0 if success else 1)
