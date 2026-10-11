"""
demo_scan.py  -  Runs scan_dependencies against realistic manifests and
                 demonstrates the unreachable-OSV code path.
Run from: backend/ directory as: .venv\Scripts\python.exe scripts\demo_scan.py
"""
import sys, os, json, pathlib, tempfile, re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from unittest.mock import MagicMock
from backend.sca.osv_client import OSVClient, OSVClientError
from backend.sca.scanner import scan_dependencies
from backend.sca.parsers import parse_manifests_in_directory

REQ_TXT = "requests==2.19.0\nDjango==2.1.0\nflask>=2.0\npillow\n"

PACKAGE_LOCK = json.dumps({
    "lockfileVersion": 2,
    "packages": {
        "": {"dependencies": {"lodash": "4.17.20"}},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/express": {"version": "4.18.2"},
    }
})

POM_XML = (
    "<project><dependencies><dependency>"
    "<groupId>org.apache.logging.log4j</groupId>"
    "<artifactId>log4j-core</artifactId>"
    "<version>2.14.1</version>"
    "</dependency></dependencies></project>"
)

with tempfile.TemporaryDirectory() as tmp:
    tmp_path = pathlib.Path(tmp)
    (tmp_path / "requirements.txt").write_text(REQ_TXT)
    (tmp_path / "package-lock.json").write_text(PACKAGE_LOCK)
    (tmp_path / "pom.xml").write_text(POM_XML)

    deps, unresolved, _ = parse_manifests_in_directory(str(tmp_path))

    print("=" * 65)
    print("PARSED DEPENDENCIES (will be queried via OSV)")
    print("=" * 65)
    hdr = f"{'file':<22} {'eco':<8} {'package':<45} {'version':<12} {'direct':<8} {'dev'}"
    print(hdr)
    print("-" * len(hdr))
    for d in deps:
        fname = os.path.basename(d.manifest_file)
        print(f"{fname:<22} {d.ecosystem:<8} {d.name:<45} {d.version:<12} {str(d.direct):<8} {d.dev}")

    print()
    print("NOT CHECKED (unpinned / unresolvable):")
    for u in unresolved:
        print(f"  {os.path.basename(u.manifest_file)}: {u.name}  reason={u.reason!r}")

    # ── mock OSV responses ──────────────────────────────────────────────────
    def make_adv(aid, severity, pkg, eco, fixed_ver):
        evts = [{"introduced": "0"}]
        if fixed_ver:
            evts.append({"fixed": fixed_ver})
        return {
            "id": aid,
            "aliases": [],
            "summary": f"Vulnerability in {pkg}",
            "database_specific": {"severity": severity, "cwe_ids": ["CWE-400"]},
            "affected": [{"package": {"name": pkg, "ecosystem": eco},
                          "ranges": [{"events": evts}]}],
        }

    mock_map = {
        ("PyPI", "requests", "2.19.0"):    ["GHSA-j8r2-6x86-q33q"],
        ("PyPI", "django",   "2.1.0"):     ["GHSA-2hfj-cxw7-g45p"],
        ("npm",  "lodash",   "4.17.20"):   ["GHSA-29mw-wpgm-hmr9"],
        ("npm",  "express",  "4.18.2"):    [],
        ("Maven","org.apache.logging.log4j:log4j-core","2.14.1"): ["GHSA-jfh8-c2jp-5v3q"],
    }
    mock_advisories = {
        "GHSA-j8r2-6x86-q33q": make_adv("GHSA-j8r2-6x86-q33q","HIGH","requests","PyPI","2.28.0"),
        "GHSA-2hfj-cxw7-g45p": make_adv("GHSA-2hfj-cxw7-g45p","CRITICAL","django","PyPI","2.2.0"),
        "GHSA-29mw-wpgm-hmr9": make_adv("GHSA-29mw-wpgm-hmr9","HIGH","lodash","npm","4.17.21"),
        "GHSA-jfh8-c2jp-5v3q": make_adv("GHSA-jfh8-c2jp-5v3q","CRITICAL",
                                         "org.apache.logging.log4j:log4j-core","Maven","2.17.1"),
    }

    mock_client = MagicMock(spec=OSVClient)
    mock_client.query_batch.return_value = (mock_map, [])
    mock_client.fetch_advisories.return_value = (mock_advisories, [])

    findings, warnings, summary = scan_dependencies(str(tmp_path), client=mock_client)

    print()
    print("=" * 65)
    print("SCAN FINDINGS TABLE")
    print("=" * 65)

    # Extract info from description field:  "Package 'X' version 'V' in F has N advisory..."
    pkg_re = re.compile(r"Package '([^']+)' version '([^']+)' in ([^ ]+) has (\d+)")
    rec_re = re.compile(r"Recommended version: >= ([^\s]+)|Manual upgrade")
    # Advisory IDs appear in recommendation as [GHSA-xxxx](url)
    aid_re = re.compile(r"\[([A-Z0-9]+-[A-Z0-9-]+)\]")

    hdr2 = f"{'file':<22} {'package':<40} {'ver':<10} {'sev':<10} {'advisory_ids':<25} {'rec_ver':<12} {'direct'}"
    print(hdr2)
    print("-" * len(hdr2))
    for f in findings:
        fname = os.path.basename(f.file_path)
        m = pkg_re.search(f.description or "")
        pkg = m.group(1) if m else "?"
        ver = m.group(2) if m else "?"
        # direct/transitive from recommendation
        direct = "direct" if "Direct" in (f.recommendation or "") else "transitive"
        # advisory IDs
        adv_ids = ", ".join(aid_re.findall(f.recommendation or "")[:3])
        # recommended version
        rm = rec_re.search(f.description or "")
        rec_ver = rm.group(1) if rm and rm.group(1) else "—"
        print(f"{fname:<22} {pkg:<40} {ver:<10} {f.severity:<10} {adv_ids:<25} {rec_ver:<12} {direct}")

    print()
    print(f"Summary: {summary}")
    print(f"Warnings: {warnings}")

    # ── unreachable OSV ─────────────────────────────────────────────────────
    print()
    print("=" * 65)
    print("UNREACHABLE OSV (base_url=http://127.0.0.1:19999)")
    print("=" * 65)
    dead_client = OSVClient(base_url="http://127.0.0.1:19999")
    findings2, warnings2, summary2 = scan_dependencies(str(tmp_path), client=dead_client)
    print(f"findings count : {len(findings2)}")
    print(f"dependency_summary: {summary2}")
    print("warnings:")
    for w in warnings2:
        print(f"  - {w}")
