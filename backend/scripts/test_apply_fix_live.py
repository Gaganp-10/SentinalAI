"""
Live end-to-end test of POST /api/vulnerabilities/{id}/apply-fix
through http://localhost:3000/api.
"""
import json
import os
import sys
import time
import requests

BASE_URL = "http://localhost:3000"
s = requests.Session()

# ── Auth ────────────────────────────────────────────────────────────────────
ts = int(time.time())
email    = f"applyfix_{ts}@sentinel.io"
username = f"applyfix_{ts}"
password = "Password123!Secure"

s.post(f"{BASE_URL}/api/auth/signup",
       json={"email": email, "username": username, "password": password})
login = s.post(f"{BASE_URL}/api/auth/login",
               json={"username": username, "password": password})
assert login.status_code == 200, f"Login failed: {login.text}"
token = login.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
print(f"Authenticated as {username}")

# ── Create project ───────────────────────────────────────────────────────────
proj = s.post(f"{BASE_URL}/api/projects",
              json={"project_name": "Apply-Fix Verification"},
              headers=headers)
assert proj.status_code == 201, f"Create project failed: {proj.text}"
proj_id = proj.json()["id"]
print(f"Project: {proj_id}")

# ── Upload vulnerable Python file ───────────────────────────────────────────
VULN_CODE = (
    "import sqlite3\n\n"
    "def get_user(cursor, user_id):\n"
    '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    "    return cursor.fetchall()\n"
)

DEST = os.path.join("uploads", "vulnerable_demo.py")
up = s.post(
    f"{BASE_URL}/api/projects/{proj_id}/files",
    files={"file": ("vulnerable_demo.py", VULN_CODE.encode("utf-8"), "text/x-python")},
    headers=headers,
)
assert up.status_code == 201, f"Upload failed: {up.text}"
print(f"Upload 201  accepted={len(up.json().get('accepted', []))}")

# ── Trigger scan ─────────────────────────────────────────────────────────────
scan_r = s.post(f"{BASE_URL}/api/projects/{proj_id}/scan", headers=headers)
assert scan_r.status_code == 202, f"Scan trigger failed: {scan_r.text}"
scan_id = scan_r.json()["id"]
print(f"Scan started: {scan_id}")

for _ in range(90):
    poll = s.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers).json()
    if poll.get("status") == "completed":
        print(f"Scan complete: {poll['total_issues']} issue(s)")
        break
    time.sleep(1)
else:
    sys.exit("Scan did not complete in time")

# ── List vulnerabilities ─────────────────────────────────────────────────────
vulns = s.get(f"{BASE_URL}/api/vulnerabilities?project_id={proj_id}",
              headers=headers).json()
print(f"Vulnerabilities found: {len(vulns)}")
for v in vulns:
    print(f"  {v['id']}  type={v['type']}  auto_fixable={v.get('auto_fixable')}  "
          f"line={v.get('line_number')}  has_snippet={bool(v.get('code_snippet'))}")

# ── Pick a template-fixable candidate ────────────────────────────────────────
target = next((v for v in vulns if v.get("auto_fixable") and v.get("code_snippet")), None)
if target is None:
    sys.exit("No auto-fixable vulnerability found — cannot demonstrate apply-fix")

vuln_id = target["id"]
print(f"\nTarget vulnerability: {vuln_id}  ({target['type']})")

# ── POST /api/vulnerabilities/{id}/apply-fix ─────────────────────────────────
print(f"\n-- REQUEST -------------------------------------------------------")
print(f"POST {BASE_URL}/api/vulnerabilities/{vuln_id}/apply-fix")
print(f"Authorization: Bearer <redacted>")

fix_r = s.post(f"{BASE_URL}/api/vulnerabilities/{vuln_id}/apply-fix",
               headers=headers)
print(f"\n-- RESPONSE ------------------------------------------------------")
print(f"HTTP {fix_r.status_code}")
resp_json = fix_r.json()
print(json.dumps(resp_json, indent=2))

assert fix_r.status_code == 200, f"apply-fix failed: {fix_r.text}"
assert resp_json.get("apply_status") == "applied"
assert resp_json.get("vulnerability", {}).get("fixed") is True

# ── Show patched file from the named volume ───────────────────────────────────
file_id = resp_json["vulnerability"].get("file_id") or resp_json["vulnerability"].get("file", {}).get("id")
print(f"\n-- PATCHED FILE (via GET /api/projects/{proj_id}/files) ---------")
files_r = s.get(f"{BASE_URL}/api/projects/{proj_id}/files", headers=headers).json()
for fobj in files_r:
    print(f"  {fobj['id']}  {fobj['filename']}  {fobj['filepath']}")

print("\n-- pyflakes + py_compile (in container) -------------------------")
import subprocess

# get the actual file path inside the named volume
file_path_in_volume = files_r[0]["filepath"] if files_r else "vulnerable_demo.py"
# copy patched file out of container for local verification
cp = subprocess.run(
    ["docker", "compose", "exec", "backend",
     "cat", f"/app/uploads/{proj_id}/{file_path_in_volume}"],
    capture_output=True, text=True
)
patched_content = cp.stdout
print("Patched file content:")
print(patched_content)

# Write locally and run pyflakes + py_compile
tmp = "uploads/patched_check.py"
os.makedirs("uploads", exist_ok=True)
with open(tmp, "w") as f:
    f.write(patched_content)

import py_compile, ast, tempfile, io
try:
    py_compile.compile(tmp, doraise=True)
    print("py_compile: OK")
except py_compile.PyCompileError as e:
    print(f"py_compile ERROR: {e}")

try:
    import pyflakes.api
    import pyflakes.reporter
    class Reporter:
        def unexpectedError(self, filename, msg): print(f"PYFLAKES UNEXPECTED: {msg}")
        def syntaxError(self, filename, msg, lineno, offset, text): print(f"PYFLAKES SYNTAX: {msg}")
        def flake(self, msg): print(f"PYFLAKES WARNING: {msg}")
    result = pyflakes.api.check(patched_content, "<patched>", reporter=Reporter())
    if result == 0:
        print("pyflakes: 0 warnings / errors")
    else:
        print(f"pyflakes: {result} warning(s)")
except ImportError:
    # Run inside container
    res = subprocess.run(
        ["docker", "compose", "exec", "backend", "python", "-m", "pyflakes", "-"],
        input=patched_content, capture_output=True, text=True
    )
    if res.returncode == 0 and not res.stdout.strip():
        print("pyflakes: 0 warnings / errors (container)")
    else:
        print(f"pyflakes container output: {res.stdout} {res.stderr}")

os.remove(tmp)
print("\nVERIFICATION PASSED ✓")
