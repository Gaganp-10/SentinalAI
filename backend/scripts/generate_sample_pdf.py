import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import json
from uuid import uuid4
from datetime import datetime, timezone
from backend.reports.pdf_report import generate_pdf_report_for_project
from backend.models.models import Project, ScanHistory, Vulnerability, File

proj = Project(
    id=uuid4(),
    project_name="SentinelAI SCA Demo Project",
    scan_date=datetime.now(timezone.utc)
)

scan = ScanHistory(
    id=uuid4(),
    project_id=proj.id,
    scan_time=datetime.now(timezone.utc),
    total_issues=1,
    critical_count=0,
    high_count=1,
    medium_count=0,
    low_count=0,
    status="completed",
    warnings=json.dumps(["1 unpinned package(s) in requirements.txt not checked against OSV: flask>=2.0"]),
    dependency_summary=json.dumps({"checked": 5, "failed": 0, "not_checked": 1, "manifests": 2})
)

manifest_file = File(
    id=uuid4(),
    project_id=proj.id,
    filename="package.json",
    filepath="package.json",
    language="manifest",
    size=256
)
proj.files = [manifest_file]

vuln = Vulnerability(
    id=uuid4(),
    file_id=manifest_file.id,
    type="vulnerable_dependency",
    line_number=1,
    severity="high",
    description="Package 'lodash' version '4.17.15' in package.json has 6 known vulnerability advisory(s). Recommended version: >= 4.18.0",
    code_snippet="lodash@4.17.15 (package.json)",
    suggested_fix="Update lodash to >= 4.18.0",
    recommendation="""### Vulnerable Dependency: `lodash` (npm)
- **Installed Version**: `4.17.15`
- **Dependency Type**: Direct (Production dependency)
- **Manifest File**: `package.json`

#### Recommended Action
Upgrade `lodash` to **`4.18.0`** or newer to resolve all detected advisories.

#### Known Vulnerabilities (6 advisories)
- **[GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9)** [high]: Regular Expression Denial of Service (ReDoS) in lodash — Fixed in: `4.17.21`
- **[GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm)** [high]: Command Injection in lodash — Fixed in: `4.17.21`
- **[GHSA-f23m-r3pf-42rh](https://osv.dev/vulnerability/GHSA-f23m-r3pf-42rh)** [high]: Prototype Pollution in lodash — Fixed in: `4.18.0`
- **[GHSA-p6mc-m468-83gw](https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw)** [high]: Prototype Pollution in lodash — Fixed in: `4.17.19`
- **[GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc)** [high]: Prototype Pollution in lodash — Fixed in: `4.18.0`
- **[GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg)** [high]: Prototype Pollution in lodash — Fixed in: `4.17.23`""",
    cwe_id="CWE-1321",
    owasp_category="A06:2021-Vulnerable and Outdated Components",
    confidence=1.0,
    source_tool="osv",
    fixed=False,
    auto_fixable=False,
    fix_source=None
)
vuln.file = manifest_file

pdf_bytes = generate_pdf_report_for_project(proj, scan, [vuln])
print("PDF generated successfully:", bool(pdf_bytes), "Length:", len(pdf_bytes) if pdf_bytes else 0)

out_path = r"C:\Users\HP-PC\.gemini\antigravity-ide\brain\b878b716-9743-457b-a5a8-ebf19545e637\dependency_scan_report.pdf"
with open(out_path, "wb") as f:
    f.write(pdf_bytes)
print("Saved to:", out_path, "File size:", os.path.getsize(out_path), "bytes")
