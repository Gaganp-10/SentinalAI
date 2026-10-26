import time
import requests
import threading
import subprocess
import os

BASE_URL = "http://localhost:3000"
ZIP_PATH = r"backend\tests\test_archives\7_large_count_3000.zip"

# Authenticate
s = requests.Session()
email = f"test_upload_{int(time.time())}@sentinel.io"
username = f"uploader_{int(time.time())}"
password = "Password123!Secure"

r = s.post(f"{BASE_URL}/api/auth/signup", json={"email": email, "username": username, "password": password})
r = s.post(f"{BASE_URL}/api/auth/login", json={"username": username, "password": password})
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# Create project
proj_r = s.post(f"{BASE_URL}/api/projects", json={"project_name": "Benchmark 3000 Files"}, headers=headers)
proj_id = proj_r.json()["id"]
print(f"Created project {proj_id}")

# Memory sampler
sampling = True
mem_samples = []

def sample_memory():
    while sampling:
        try:
            out = subprocess.check_output(
                ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", "securityvulnerabilitydecoderandfixer-backend-1"],
                text=True
            ).strip()
            mem_samples.append((time.time(), out))
        except Exception as e:
            pass
        time.sleep(1)

t_sampler = threading.Thread(target=sample_memory, daemon=True)
t_sampler.start()

print(f"Starting upload of {ZIP_PATH}...")
t0 = time.time()
with open(ZIP_PATH, "rb") as f:
    files = {"file": ("7_large_count_3000.zip", f, "application/zip")}
    upload_res = s.post(f"{BASE_URL}/api/projects/{proj_id}/files", files=files, headers=headers)
t1 = time.time()
sampling = False
t_sampler.join(timeout=2)

print(f"Upload completed in {t1 - t0:.2f} s with HTTP status {upload_res.status_code}")
if upload_res.status_code == 201:
    data = upload_res.json()
    print(f"Accepted: {len(data.get('accepted', []))}, Skipped: {data.get('skipped', {})}")
else:
    print(f"Error: {upload_res.text[:300]}")

print("Memory samples during upload:")
for ts, mem in mem_samples:
    print(f"  [{ts - t0:.1f}s] {mem}")
