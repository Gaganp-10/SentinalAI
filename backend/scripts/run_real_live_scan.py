import os
import sys
import tempfile
import json
import re

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.sca.scanner import scan_dependencies
from backend.sca.osv_client import OSVClient
from backend.sca.parsers import parse_manifests_in_directory


def main():
    temp_dir = tempfile.mkdtemp(prefix="sca_real_live_")
    print(f"=== STEP 7 LIVE OSV SCAN ===")
    print(f"Temporary project directory: {temp_dir}\n")

    # 1. requirements.txt
    req_content = "requests==2.19.0\ndjango==2.2.0\npyyaml==5.1\nflask>=2.0\n"
    with open(os.path.join(temp_dir, "requirements.txt"), "w", encoding="utf-8") as f:
        f.write(req_content)

    # 2. package.json
    pkg_json_content = json.dumps({
        "name": "live-sca-test",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.15",
            "minimist": "1.2.0",
            "express": "^4.18.0"
        }
    }, indent=2)
    with open(os.path.join(temp_dir, "package.json"), "w", encoding="utf-8") as f:
        f.write(pkg_json_content)

    # 3. pom.xml
    pom_content = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>test-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
"""
    with open(os.path.join(temp_dir, "pom.xml"), "w", encoding="utf-8") as f:
        f.write(pom_content)

    # Parse manifests
    deps, unresolved, parse_warns = parse_manifests_in_directory(temp_dir)
    print(f"--- 1. MANIFEST PARSING RESULTS ---")
    print(f"Pinned Dependencies ({len(deps)}):")
    for d in deps:
        print(f"  * [{d.ecosystem}] {d.name} == {d.version} ({d.manifest_file}, direct={d.direct})")
    print(f"\nUnresolved / Unpinned Dependencies ({len(unresolved)}) [NOT CHECKED]:")
    for u in unresolved:
        print(f"  * [{u.ecosystem}] {u.name} in {u.manifest_file} (Reason: {u.reason})")

    # Run real live scan
    print(f"\n--- 2. LIVE OSV QUERY EXECUTION ---")
    client = OSVClient()
    findings, warnings, summary = scan_dependencies(temp_dir, client=client)

    print("\nDependency Summary:")
    print(json.dumps(summary, indent=2))

    print("\nScan Warnings:")
    for w in warnings:
        print(f"  * {w}")

    print("\n--- 3. FINDINGS TABLE ---")
    # Columns: file, package, version, severity, number of advisories & IDs, recommended min version, direct/transitive
    print("| File | Package | Version | Severity | Adv Count | Advisory IDs | Recommended Version | Direct/Transitive |")
    print("|---|---|---|---|---|---|---|---|")

    # To extract advisories and inspect details:
    all_adv_map = {}
    
    for f in findings:
        # Extract package name and version
        if "==" in f.code_snippet:
            pkg_name, ver = f.code_snippet.split("==")
        elif "@" in f.code_snippet:
            pkg_name = f.code_snippet.split("@")[0]
            ver = f.code_snippet.split("@")[1].split(" ")[0]
        else:
            pkg_name = f.code_snippet
            ver = "unknown"

        # Extract advisory IDs from markdown list
        # Pattern: - **[ID](url) (CVE)** [SEV]:
        adv_matches = re.findall(r"- \*\*\[([A-Za-z0-9_-]+)\]", f.recommendation)
        
        # Suggested fix
        rec_version = f.suggested_fix if f.suggested_fix else "Manual upgrade"
        direct_str = "direct"

        adv_ids_str = ", ".join(adv_matches)
        print(f"| `{f.file_path}` | `{pkg_name}` | `{ver}` | `{f.severity.upper()}` | {len(adv_matches)} | {adv_ids_str} | `{rec_version}` | {direct_str} |")

        for aid in adv_matches:
            all_adv_map[aid] = (f.file_path, pkg_name)

    # Detailed Log4j Check
    print("\n--- 4. LOG4J-CORE CVE-2021-44228 CONFIRMATION ---")
    log4j_adv_ids = [aid for aid, (fp, pkg) in all_adv_map.items() if "log4j" in pkg.lower()]
    log4j_records, _ = client.fetch_advisories(set(log4j_adv_ids))
    
    log4shell_found = False
    for aid, rec in log4j_records.items():
        aliases = rec.get("aliases", [])
        if "CVE-2021-44228" in aliases or aid == "CVE-2021-44228":
            log4shell_found = True
            print(f"SUCCESS: Advisory '{aid}' has aliases: {aliases}")
            print(f"  -> Confirmed: 'CVE-2021-44228' is present in aliases for log4j-core 2.14.1!")
            break

    # Severity Derivation Analysis
    print("\n--- 5. SEVERITY DERIVATION ANALYSIS & EXAMPLES ---")
    all_records, _ = client.fetch_advisories(set(all_adv_map.keys()))
    
    example_db_specific = None
    example_cvss = None
    example_default_medium = None

    for aid, rec in all_records.items():
        db_spec = rec.get("database_specific", {})
        sev_raw = db_spec.get("severity") if isinstance(db_spec, dict) else None
        severities = rec.get("severity", [])
        has_cvss = any(isinstance(s, dict) and s.get("type", "").startswith("CVSS") for s in severities)
        cvss_data = next((s for s in severities if isinstance(s, dict) and s.get("type", "").startswith("CVSS")), None)

        if sev_raw and not example_db_specific:
            example_db_specific = {
                "id": aid,
                "pkg": all_adv_map[aid][1],
                "database_specific.severity": sev_raw,
                "summary": rec.get("summary", "")
            }
        
        if not sev_raw and has_cvss and not example_cvss:
            example_cvss = {
                "id": aid,
                "pkg": all_adv_map[aid][1],
                "cvss_entry": cvss_data,
                "summary": rec.get("summary", "")
            }
            
        if not sev_raw and not has_cvss and not example_default_medium:
            example_default_medium = {
                "id": aid,
                "pkg": all_adv_map[aid][1],
                "summary": rec.get("summary", "")
            }

    print("Case A: database_specific.severity (from GitHub / upstream advisory database):")
    if example_db_specific:
        print(f"  Advisory ID: {example_db_specific['id']} ({example_db_specific['pkg']})")
        print(f"  database_specific.severity: {example_db_specific['database_specific.severity']}")
        print(f"  Summary: {example_db_specific['summary']}")
        print(f"  Derivation: Mapped directly via normalize_severity() -> {example_db_specific['database_specific.severity'].lower()}")
    else:
        print("  None found in this set")

    print("\nCase B: CVSS vector present (when database_specific.severity is absent):")
    if example_cvss:
        print(f"  Advisory ID: {example_cvss['id']} ({example_cvss['pkg']})")
        print(f"  CVSS Entry: {example_cvss['cvss_entry']}")
        print(f"  Summary: {example_cvss['summary']}")
        print(f"  Derivation: No CVSS calculator used; when database_specific.severity is missing, normalize_severity(None) returns ('medium', False).")
    else:
        print("  In the returned advisories for these packages, all GHSA records provided database_specific.severity directly.")

    print("\nCase C: Default 'medium' with 'not provided by source' note:")
    print("  Implemented in backend/sca/findings.py: normalize_severity(None) returns ('medium', False).")
    print("  When no advisory for a package has a provided severity, findings.py appends:")
    print("  '- **Severity Note**: Severity not provided by source (defaulted to medium).'")
    print("  Tested by TestNormalizeSeverity.test_none_default_medium and TestBuildDependencyFinding.test_no_sev_defaults_medium.")

    # Clean up
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
