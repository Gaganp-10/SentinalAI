"""Generate real scan diff JSON from Docker run."""
import json
import time
import requests

BASE_URL = "http://localhost:3000"
s = requests.Session()

ts = int(time.time())
s.post(f"{BASE_URL}/api/auth/signup",
       json={"email": f"diff_{ts}@sentinel.io", "username": f"diff_{ts}", "password": "Password123!Secure"})
login = s.post(f"{BASE_URL}/api/auth/login",
               json={"username": f"diff_{ts}", "password": "Password123!Secure"})
token = login.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
print("Authenticated.")

proj = s.post(f"{BASE_URL}/api/projects", json={"project_name": "Diff Demo"}, headers=headers)
pid = proj.json()["id"]
print(f"Project: {pid}")

# Vuln code (matching template for python sqli in vulnerable_demo.py)
code1 = (
    "import sqlite3\n\n"
    "def get_user(cursor, user_id):\n"
    '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    "    return cursor.fetchall()\n"
).encode("utf-8")
s.post(f"{BASE_URL}/api/projects/{pid}/files",
       files={"file": ("vulnerable_demo.py", code1, "text/x-python")}, headers=headers)

# Scan 1
scan1 = s.post(f"{BASE_URL}/api/projects/{pid}/scan", headers=headers)
scan1_id = scan1.json()["id"]
for _ in range(90):
    p = s.get(f"{BASE_URL}/api/scans/{scan1_id}", headers=headers).json()
    if p.get("status") == "completed":
        print(f"Scan 1 complete: {p['total_issues']} issue(s)")
        break
    time.sleep(1)

# Apply-fix
vulns = s.get(f"{BASE_URL}/api/vulnerabilities?project_id={pid}", headers=headers).json()
fix_t = next((v for v in vulns if v.get("auto_fixable")), None)
if fix_t:
    fix_r = s.post(f"{BASE_URL}/api/vulnerabilities/{fix_t['id']}/apply-fix", headers=headers)
    print(f"apply-fix: HTTP {fix_r.status_code}")

# Scan 2
scan2 = s.post(f"{BASE_URL}/api/projects/{pid}/scan", headers=headers)
scan2_id = scan2.json()["id"]
for _ in range(90):
    p2 = s.get(f"{BASE_URL}/api/scans/{scan2_id}", headers=headers).json()
    if p2.get("status") == "completed":
        print(f"Scan 2 complete: {p2['total_issues']} issue(s)")
        break
    time.sleep(1)

# Diff
diff_r = s.get(f"{BASE_URL}/api/projects/{pid}/scans/{scan2_id}/diff?base={scan1_id}", headers=headers)
print(f"\nDiff status: HTTP {diff_r.status_code}")
diff_data = diff_r.json()
print(json.dumps(diff_data, indent=2))
