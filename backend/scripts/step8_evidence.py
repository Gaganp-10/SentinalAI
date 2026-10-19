import os, sys, json, time, hashlib
from datetime import datetime, timedelta
from uuid import uuid4

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
from backend.models.models import Base, User, Project, File, ScanHistory, ScanFinding
Base.metadata.create_all(bind=engine)
Session = sessionmaker(bind=engine)
db = Session()

from backend.detectors.diff import compute_scan_diff
from backend.detectors.fingerprint import (
    compute_code_fingerprint, compute_dependency_fingerprint,
    assign_fingerprints, normalize_snippet
)
from backend.detectors.schema import Finding


def make_user():
    u = User(id=uuid4(), username="ev_user", email="ev@s.ai", hashed_password="x", is_active=True)
    db.add(u); db.commit(); return u


def make_project(user, name):
    p = Project(id=uuid4(), user_id=user.id, project_name=name)
    db.add(p); db.commit(); return p


def add_file(project, filepath):
    f = File(id=uuid4(), project_id=project.id,
             filename=os.path.basename(filepath), filepath=filepath, size=100)
    db.add(f); db.commit(); return f


def make_scan(project, engines, scan_time=None, **kwargs):
    s = ScanHistory(
        id=uuid4(), project_id=project.id, status="completed",
        scan_time=scan_time if scan_time is not None else datetime.utcnow(),
        engines_run=json.dumps(engines), **kwargs
    )
    db.add(s); db.commit(); return s


def add_finding(scan, project, fp, file_path, ftype, severity,
                source_tools, line=10, pkg_name=None, pkg_ver=None):
    sf = ScanFinding(
        id=uuid4(), scan_id=scan.id, project_id=project.id,
        fingerprint=fp, file_path=file_path,
        type=ftype, severity=severity,
        source_tools=json.dumps(source_tools),
        line_number=line, package_name=pkg_name, package_version=pkg_ver,
    )
    db.add(sf); db.commit(); return sf


def show_diff(diff, label):
    out = {
        "summary": diff["summary"],
        "score_before": diff.get("score_before"),
        "score_after":  diff.get("score_after"),
        "severity_delta": diff.get("severity_delta"),
        "notes": diff.get("notes", []),
        "items": {},
    }
    for cat, items in (diff.get("items") or {}).items():
        out["items"][cat] = items[:2]
    print(f"\n--- DIFF: {label} ---")
    print(json.dumps(out, indent=2, default=str))


user = make_user()

# ── 2a ───────────────────────────────────────────────────────────────────────
print("\n=== SCENARIO 2a: two fixes applied (resolved=2, new=0) ===")
proj_a = make_project(user, "Proj2a")
add_file(proj_a, "app.py")
fp_sqli = compute_code_fingerprint("app.py", "SQL Injection", "SQL_INJECTION",
    "cursor.execute(select_pct_s_user_input)")
fp_cmdi = compute_code_fingerprint("app.py", "Command Injection", "COMMAND_INJECTION",
    "subprocess.call(user_cmd, shell=True)")
fp_md5  = compute_code_fingerprint("app.py", "Insecure Hash", "INSECURE_HASH",
    "hashlib.md5(data.encode()).hexdigest()")

s1a = make_scan(proj_a, ["bandit", "ast"],
    scan_time=datetime.utcnow() - timedelta(hours=2),
    critical_count=1, high_count=1, medium_count=1)
add_finding(s1a, proj_a, fp_sqli, "app.py", "SQL Injection",    "critical", ["bandit"], line=12)
add_finding(s1a, proj_a, fp_cmdi, "app.py", "Command Injection","high",     ["bandit"], line=17)
add_finding(s1a, proj_a, fp_md5,  "app.py", "Insecure Hash",   "medium",   ["bandit"], line=21)

s2a = make_scan(proj_a, ["bandit", "ast"],
    scan_time=datetime.utcnow() - timedelta(hours=1),
    critical_count=0, high_count=0, medium_count=1)
add_finding(s2a, proj_a, fp_md5, "app.py", "Insecure Hash", "medium", ["bandit"], line=21)

diff_2a = compute_scan_diff(db, s2a, s1a, proj_a)
show_diff(diff_2a, "Scan2 vs Scan1 - two fixes applied")
assert diff_2a["summary"]["resolved"] == 2
assert diff_2a["summary"]["new"] == 0
print("PASS 2a: resolved=2, new=0, persisting=1")

# ── 2b ───────────────────────────────────────────────────────────────────────
print("\n=== SCENARIO 2b: re-introduce one fixed line (regressed=1) ===")
proj_b = make_project(user, "Proj2b")
add_file(proj_b, "app.py")
fp_cmdi_b = compute_code_fingerprint("app.py", "Command Injection", "COMMAND_INJECTION",
    "subprocess.call(user_cmd, shell=True)")
fp_md5_b  = compute_code_fingerprint("app.py", "Insecure Hash", "INSECURE_HASH",
    "hashlib.md5(data.encode()).hexdigest()")

s1b = make_scan(proj_b, ["bandit"], scan_time=datetime.utcnow() - timedelta(hours=3))
add_finding(s1b, proj_b, fp_cmdi_b, "app.py", "Command Injection","high",   ["bandit"], line=17)
add_finding(s1b, proj_b, fp_md5_b,  "app.py", "Insecure Hash",   "medium", ["bandit"], line=21)

s2b = make_scan(proj_b, ["bandit"], scan_time=datetime.utcnow() - timedelta(hours=2))
# both fixed — no findings

s3b = make_scan(proj_b, ["bandit"], scan_time=datetime.utcnow() - timedelta(hours=1))
add_finding(s3b, proj_b, fp_cmdi_b, "app.py", "Command Injection","high", ["bandit"], line=17)

diff_2b = compute_scan_diff(db, s3b, s2b, proj_b)
show_diff(diff_2b, "Scan3 vs Scan2 - one regression")
assert diff_2b["summary"]["regressed"] == 1
assert diff_2b["summary"]["new"] == 0
print("PASS 2b: regressed=1, new=0")

# ── 2c ───────────────────────────────────────────────────────────────────────
print("\n=== SCENARIO 2c: 10 blank lines inserted (fingerprint stable, no new/resolved) ===")
proj_c = make_project(user, "Proj2c")
add_file(proj_c, "app.py")

fp_before = compute_code_fingerprint("app.py", "Command Injection", "COMMAND_INJECTION",
    "17: subprocess.call(user_cmd, shell=True)")
fp_after  = compute_code_fingerprint("app.py", "Command Injection", "COMMAND_INJECTION",
    "   27:    subprocess.call(user_cmd, shell=True)   ")
print(f"fp_before (line 17): {fp_before}")
print(f"fp_after  (line 27): {fp_after}")
assert fp_before == fp_after, "fingerprints must match after line shift"
print("Fingerprints are identical — line shift absorbed by normalization")

s1c = make_scan(proj_c, ["bandit"], scan_time=datetime.utcnow() - timedelta(hours=2))
add_finding(s1c, proj_c, fp_before, "app.py", "Command Injection","high", ["bandit"], line=17)

s2c = make_scan(proj_c, ["bandit"], scan_time=datetime.utcnow() - timedelta(hours=1))
add_finding(s2c, proj_c, fp_after, "app.py", "Command Injection","high", ["bandit"], line=27)

diff_2c = compute_scan_diff(db, s2c, s1c, proj_c)
show_diff(diff_2c, "Scan2 vs Scan1 - blank lines inserted")
assert diff_2c["summary"]["new"] == 0
assert diff_2c["summary"]["resolved"] == 0
assert diff_2c["summary"]["persisting"] == 1
print("PASS 2c: new=0, resolved=0, persisting=1")

# ── 2d ───────────────────────────────────────────────────────────────────────
print("\n=== SCENARIO 2d: broken Semgrep path (not_comparable, not resolved) ===")
proj_d = make_project(user, "Proj2d")
add_file(proj_d, "index.js")
fp_xss = "semgrep_xss_" + hashlib.sha256(b"index.js|dom_xss|eval(userInput)").hexdigest()[:20]

s1d = make_scan(proj_d, ["semgrep"], scan_time=datetime.utcnow() - timedelta(hours=2))
add_finding(s1d, proj_d, fp_xss, "index.js", "DOM XSS", "high", ["semgrep"], line=2)

s2d = make_scan(proj_d, ["bandit", "ast"], scan_time=datetime.utcnow() - timedelta(hours=1))

diff_2d = compute_scan_diff(db, s2d, s1d, proj_d)
show_diff(diff_2d, "Scan2 vs Scan1 - semgrep did not run")
assert diff_2d["summary"]["resolved"] == 0
assert diff_2d["summary"]["not_comparable"] == 1
nc = diff_2d["items"]["not_comparable"][0]
assert "semgrep" in nc["reason"].lower()
print("not_comparable[0].reason:", repr(nc["reason"]))
print("notes:", diff_2d["notes"])
print("PASS 2d: resolved=0, not_comparable=1, reason contains 'semgrep'")

# ── 2e ───────────────────────────────────────────────────────────────────────
print("\n=== SCENARIO 2e: JS file removed (not_comparable: file not scanned) ===")
proj_e = make_project(user, "Proj2e")
file_js = add_file(proj_e, "utils.js")
fp_eval = "semgrep_eval_" + hashlib.sha256(b"utils.js|eval|eval(userInput)").hexdigest()[:20]

s1e = make_scan(proj_e, ["semgrep", "bandit"], scan_time=datetime.utcnow() - timedelta(hours=2))
add_finding(s1e, proj_e, fp_eval, "utils.js", "Code Injection via eval()", "critical", ["semgrep"], line=2)

db.delete(file_js); db.commit()  # file removed from project

s2e = make_scan(proj_e, ["semgrep", "bandit"], scan_time=datetime.utcnow() - timedelta(hours=1))

diff_2e = compute_scan_diff(db, s2e, s1e, proj_e)
show_diff(diff_2e, "Scan2 vs Scan1 - utils.js removed")
assert diff_2e["summary"]["resolved"] == 0
assert diff_2e["summary"]["not_comparable"] == 1
nc_e = diff_2e["items"]["not_comparable"][0]
assert "file not scanned" in nc_e["reason"]
print("not_comparable[0].reason:", repr(nc_e["reason"]))
print("PASS 2e: resolved=0, not_comparable=1")

# ── 2f ───────────────────────────────────────────────────────────────────────
print("\n=== SCENARIO 2f: dep upgraded (still vulnerable) — persisting + version note ===")
proj_f = make_project(user, "Proj2f")
add_file(proj_f, "requirements.txt")

dep_fp = compute_dependency_fingerprint("requirements.txt", "PyPI", "django")
print(f"Dependency fingerprint (version-agnostic): {dep_fp}")
print("Key = 'requirements.txt|pypi|django'  (version excluded by design)")

s1f = make_scan(proj_f, ["osv"], scan_time=datetime.utcnow() - timedelta(hours=2))
add_finding(s1f, proj_f, dep_fp, "requirements.txt",
    "vulnerable_dependency", "high", ["osv"], line=1,
    pkg_name="django", pkg_ver="2.2.0")

s2f = make_scan(proj_f, ["osv"], scan_time=datetime.utcnow() - timedelta(hours=1))
add_finding(s2f, proj_f, dep_fp, "requirements.txt",
    "vulnerable_dependency", "high", ["osv"], line=1,
    pkg_name="django", pkg_ver="2.2.28")

diff_2f = compute_scan_diff(db, s2f, s1f, proj_f)
show_diff(diff_2f, "django 2.2.0 -> 2.2.28 (both vulnerable)")
assert diff_2f["summary"]["persisting"] == 1
assert diff_2f["summary"]["resolved"] == 0
item_f = diff_2f["items"]["persisting"][0]
assert item_f["old_version"] == "2.2.0"
assert item_f["new_version"] == "2.2.28"
assert "2.2.0 to 2.2.28" in item_f["note"]
print("persisting[0].old_version:", repr(item_f["old_version"]))
print("persisting[0].new_version:", repr(item_f["new_version"]))
print("persisting[0].note:", repr(item_f["note"]))
print("PASS 2f: persisting=1, version note present")

# ── ITEM 3: Timing ───────────────────────────────────────────────────────────
print("\n=== ITEM 3: Timing benchmark (3000 ScanFinding rows) ===")
proj_bench = make_project(user, "Bench")
for i in range(50):
    add_file(proj_bench, f"src/m{i}/f{i}.py")

bench_base = make_scan(proj_bench, ["bandit", "ast", "semgrep", "osv"],
    scan_time=datetime.utcnow() - timedelta(minutes=10))

base_rows = [
    ScanFinding(
        id=uuid4(), scan_id=bench_base.id, project_id=proj_bench.id,
        fingerprint=f"bfp_{i:05d}",
        file_path=f"src/m{i % 50}/f{i % 50}.py",
        type="sql_injection", severity="high",
        line_number=10 + (i % 100), source_tools='["bandit"]',
    )
    for i in range(3000)
]
t0 = time.perf_counter()
db.bulk_save_objects(base_rows); db.commit()
t_write = (time.perf_counter() - t0) * 1000
print(f"Snapshot bulk-write 3000 ScanFinding rows: {t_write:.2f} ms")

bench_tgt = make_scan(proj_bench, ["bandit", "ast", "semgrep", "osv"],
    scan_time=datetime.utcnow())

target_rows = [
    ScanFinding(
        id=uuid4(), scan_id=bench_tgt.id, project_id=proj_bench.id,
        fingerprint=f"bfp_{i:05d}",
        file_path=f"src/m{i % 50}/f{i % 50}.py",
        type="sql_injection", severity="high",
        line_number=15 + (i % 100), source_tools='["bandit"]',
    )
    for i in range(2500)
] + [
    ScanFinding(
        id=uuid4(), scan_id=bench_tgt.id, project_id=proj_bench.id,
        fingerprint=f"new_{i:05d}",
        file_path=f"src/m{i % 50}/f{i % 50}.py",
        type="weak_cryptography", severity="medium",
        line_number=5, source_tools='["bandit"]',
    )
    for i in range(500)
]
db.bulk_save_objects(target_rows); db.commit()

sf_count = db.query(ScanFinding).filter(ScanFinding.project_id == proj_bench.id).count()
t0 = time.perf_counter()
diff_bench = compute_scan_diff(db, bench_tgt, bench_base, proj_bench)
t_diff = (time.perf_counter() - t0) * 1000
print(f"Diff computation 3000 findings: {t_diff:.2f} ms")
print(f"Total ScanFinding rows in project: {sf_count}")
print(f"Diff summary: {json.dumps(diff_bench['summary'])}")

# ── ITEM 5: Fingerprint unit tests ───────────────────────────────────────────
print("\n=== ITEM 5: Fingerprint unit tests (in-process) ===")
passed = 0; total = 0

def chk(name, cond, detail=""):
    global passed, total
    total += 1
    if cond:
        passed += 1
        print(f"  [PASS] {name}" + (f" | {detail}" if detail else ""))
    else:
        print(f"  [FAIL] {name}" + (f" | {detail}" if detail else ""))

chk("normalize_snippet strips line-number prefix",
    normalize_snippet("  12:   import hashlib") == "import hashlib")
chk("normalize_snippet collapses multiline whitespace",
    normalize_snippet("  12:   import hashlib\n  13:   h = hashlib.md5()   ") ==
    "import hashlib h = hashlib.md5()")
chk("normalize_snippet empty string",  normalize_snippet("") == "")
chk("normalize_snippet None",          normalize_snippet(None) == "")

fp1 = compute_code_fingerprint("app/auth.py","Insecure Hash","INSECURE_HASH","12: hashlib.md5(passwd)")
fp2 = compute_code_fingerprint("app/auth.py","Insecure Hash","INSECURE_HASH","   22:    hashlib.md5(passwd)   ")
chk("fingerprint survives line-shift + whitespace", fp1 == fp2,
    f"fp1={fp1[:16]}...  fp2={fp2[:16]}...")

fpa = compute_code_fingerprint("app/a.py","Insecure Hash","INSECURE_HASH","hashlib.md5(x)")
fpb = compute_code_fingerprint("app/b.py","Insecure Hash","INSECURE_HASH","hashlib.md5(x)")
chk("different files produce different fingerprints", fpa != fpb)

f1 = Finding(file_path="app/c.py", line_number=10, type="IH", severity="medium",
             description="d", code_snippet="hashlib.md5(x)", issue_class="INSECURE_HASH")
f2 = Finding(file_path="app/c.py", line_number=30, type="IH", severity="medium",
             description="d2", code_snippet="hashlib.md5(x)", issue_class="INSECURE_HASH")
fps = assign_fingerprints([f1, f2])
chk("occurrence index distinguishes identical lines",
    fps[0] != fps[1] and ":2" in fps[1],
    f"fps[0]={fps[0][:16]}...  fps[1]={fps[1][:16]}...")

d1 = compute_dependency_fingerprint("requirements.txt","PyPI","django")
d2 = compute_dependency_fingerprint("requirements.txt","PyPI","django")
chk("dep fingerprint version-agnostic (same result both calls)", d1 == d2)

d3 = compute_dependency_fingerprint("requirements.txt","PyPI","requests")
chk("different packages produce different dep fingerprints", d1 != d3)

print(f"\nFingerprint unit tests: {passed}/{total} passed")

print("\n=== ALL EVIDENCE ITEMS COMPLETE ===")
db.close()
