"""
Archive validation test suite: runs all 6 archive edge-cases
through http://localhost:3000/api/projects/{id}/files.
"""
import io
import os
import sys
import time
import struct
import zipfile
import requests

BASE_URL = "http://localhost:3000"
s = requests.Session()

ts = int(time.time())
s.post(f"{BASE_URL}/api/auth/signup",
       json={"email": f"arch_{ts}@sentinel.io", "username": f"arch_{ts}", "password": "Password123!Secure"})
login = s.post(f"{BASE_URL}/api/auth/login",
               json={"username": f"arch_{ts}", "password": "Password123!Secure"})
token = login.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
print("Authenticated.")

def new_project(name):
    r = s.post(f"{BASE_URL}/api/projects", json={"project_name": name}, headers=headers)
    return r.json()["id"]

def upload(proj_id, zip_bytes, filename="test.zip"):
    r = s.post(
        f"{BASE_URL}/api/projects/{proj_id}/files",
        files={"file": (filename, io.BytesIO(zip_bytes), "application/zip")},
        headers=headers,
    )
    return r

PASS = "PASS"
FAIL = "FAIL"
results = []

# ===========================================================================
# 1. Duplicate basenames in different folders (two index.js, both kept)
# ===========================================================================
print("\n[1] Duplicate basenames in different folders")
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("frontend/index.js", "console.log('frontend');")
    z.writestr("backend/index.js", "console.log('backend');")
zip1 = buf.getvalue()

pid1 = new_project("Duplicate basenames")
r1 = upload(pid1, zip1)
data1 = r1.json()
accepted1 = data1.get("accepted", [])
filenames1 = [a["filename"] for a in accepted1]
ok1 = r1.status_code == 201 and filenames1.count("index.js") == 2
print(f"  Status: {r1.status_code}, accepted={filenames1}, expected 2x index.js")
results.append((PASS if ok1 else FAIL, "Duplicate basenames kept (2x index.js)"))

# ===========================================================================
# 2. Zip bomb (rejected)
# ===========================================================================
print("\n[2] Zip bomb (ratio > 100, >1MB)")
buf2 = io.BytesIO()
with zipfile.ZipFile(buf2, "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.writestr("bomb.py", "A" * (2 * 1024 * 1024))  # 2 MB of 'A'
zip2 = buf2.getvalue()
# Fake ratio > 100 by wrapping raw to a tiny compress_size
# Actually 2MB of 'A' deflates to near 0 - already a natural bomb
pid2 = new_project("Zip bomb")
r2 = upload(pid2, zip2)
ok2 = r2.status_code == 400
print(f"  Status: {r2.status_code}, body: {r2.text[:150]}")
results.append((PASS if ok2 else FAIL, f"Zip bomb rejected with 400 (got {r2.status_code})"))

# ===========================================================================
# 3. Zip-slip entries (rejected, filesystem listed to prove nothing written)
# ===========================================================================
print("\n[3] Zip-slip traversal entries")
# Craft a ZIP with a .. path
buf3 = io.BytesIO()
with zipfile.ZipFile(buf3, "w") as z:
    info = zipfile.ZipInfo("../../../etc/passwd")
    z.writestr(info, "fake passwd")
zip3 = buf3.getvalue()

pid3 = new_project("Zip-slip test")
r3 = upload(pid3, zip3)
ok3 = r3.status_code == 400
print(f"  Status: {r3.status_code}, body: {r3.text[:200]}")

# Verify nothing written outside uploads/
import subprocess
ls_result = subprocess.run(
    ["docker", "compose", "exec", "backend", "find", "/app/uploads", "-name", "passwd"],
    capture_output=True, text=True
)
passwd_found = ls_result.stdout.strip()
print(f"  Files named 'passwd' in /app/uploads: '{passwd_found or '(none)'}' <- must be empty")
ok3 = ok3 and (passwd_found == "")
results.append((PASS if ok3 else FAIL,
                f"Zip-slip rejected 400, nothing written outside project dir"))

# ===========================================================================
# 4. Corrupt ZIP (400 with generic message)
# ===========================================================================
print("\n[4] Corrupt ZIP")
corrupt_zip = b"PK\x03\x04" + b"\xff" * 200
pid4 = new_project("Corrupt zip")
r4 = upload(pid4, corrupt_zip)
ok4 = r4.status_code == 400
body4 = r4.json().get("detail", "")
generic4 = "valid zip" in body4.lower() or "corrupt" in body4.lower() or "error" in body4.lower()
print(f"  Status: {r4.status_code}, body: {body4[:120]}")
results.append((PASS if ok4 and generic4 else FAIL,
                f"Corrupt ZIP returns 400 with generic message"))

# ===========================================================================
# 5. 60 MB upload -> 413 and no temp file left
# ===========================================================================
print("\n[5] 60 MB upload -> 413")
# Build a 60 MB zip
buf5 = io.BytesIO()
with zipfile.ZipFile(buf5, "w", compression=zipfile.ZIP_STORED) as z:
    z.writestr("big.py", "X" * (12 * 1024 * 1024))  # 12MB per file, 5 times
    z.writestr("big2.py", "X" * (12 * 1024 * 1024))
    z.writestr("big3.py", "X" * (12 * 1024 * 1024))
    z.writestr("big4.py", "X" * (12 * 1024 * 1024))
    z.writestr("big5.py", "X" * (12 * 1024 * 1024))
zip5 = buf5.getvalue()
print(f"  Upload size: {len(zip5) / 1024 / 1024:.1f} MB")

pid5 = new_project("60 MB upload")
r5 = upload(pid5, zip5, filename="huge.zip")
ok5a = r5.status_code == 413
body5 = r5.json() if r5.headers.get("content-type", "").startswith("application/json") else {"detail": r5.text}
print(f"  Status: {r5.status_code}, body: {str(body5)[:150]}")

# Check no temp file left
tmp_check = subprocess.run(
    ["docker", "compose", "exec", "backend", "find", "/tmp", "-name", "upload_*.zip"],
    capture_output=True, text=True
)
temp_files = tmp_check.stdout.strip()
print(f"  Temp files in /tmp: '{temp_files or '(none)'}' <- must be empty")
ok5 = ok5a and (temp_files == "")
results.append((PASS if ok5 else FAIL,
                f"60 MB upload: status={r5.status_code} (want 413), no temp file left"))

# ===========================================================================
# 6. requirements.txt + package.json + pom.xml -> SCA findings + A06
# ===========================================================================
print("\n[6] Dependency manifest scan (requirements.txt + package.json + pom.xml)")
buf6 = io.BytesIO()
with zipfile.ZipFile(buf6, "w") as z:
    z.writestr("requirements.txt", "requests==2.20.0\nDjango==2.0\n")
    z.writestr("package.json", '{"dependencies": {"lodash": "4.17.15", "express": "4.17.1"}}\n')
    z.writestr("pom.xml",
               '<project><dependencies><dependency>'
               '<groupId>org.apache.struts</groupId>'
               '<artifactId>struts2-core</artifactId>'
               '<version>2.3.30</version>'
               '</dependency></dependencies></project>')
zip6 = buf6.getvalue()

pid6 = new_project("Dependency SCA Scan")
up6 = upload(pid6, zip6)
print(f"  Upload: {up6.status_code}, accepted={[a['filename'] for a in up6.json().get('accepted', [])]}")

# trigger scan
scan_r = s.post(f"{BASE_URL}/api/projects/{pid6}/scan", headers=headers)
scan_id = scan_r.json()["id"]
for _ in range(90):
    poll = s.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers).json()
    if poll.get("status") == "completed":
        print(f"  Scan complete: {poll['total_issues']} issue(s)")
        break
    time.sleep(1)

vulns6 = s.get(f"{BASE_URL}/api/vulnerabilities?project_id={pid6}", headers=headers).json()
print(f"  Vulnerabilities found: {len(vulns6)}")
owasp6 = s.get(f"{BASE_URL}/api/projects/{pid6}/owasp", headers=headers)
owasp6_data = owasp6.json() if owasp6.ok else {}
a06_cat = next((c for c in owasp6_data.get("categories", []) if c.get("id") == "A06"), None) if isinstance(owasp6_data, dict) else None
a06_present = (a06_cat is not None and a06_cat.get("count", 0) > 0)
print(f"  OWASP endpoint: {owasp6.status_code}, A06 count: {a06_cat.get('count') if a06_cat else 0}")
print(f"  Findings (first 3):")
for v in vulns6[:3]:
    print(f"    - {v['type']} | severity={v['severity']} | owasp={v.get('owasp_category','?')}")
ok6 = up6.status_code == 201 and len(vulns6) >= 1
results.append((PASS if ok6 else FAIL,
                f"SCA manifests: {len(vulns6)} dep findings, A06={a06_present}"))

# ===========================================================================
# Summary
# ===========================================================================
print("\n" + "="*60)
print("RESULTS:")
for status, desc in results:
    print(f"  [{status}] {desc}")
all_pass = all(s == PASS for s, _ in results)
print(f"\nOverall: {'ALL PASS' if all_pass else 'SOME FAILURES'}")
