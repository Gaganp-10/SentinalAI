import os
import time
from datetime import datetime, timezone
import pypdf
import pytest

from backend.reports.pdf_report import (
    generate_pdf_html,
    generate_pdf_report,
    generate_pdf_report_for_project,
    _calc_score,
)
from backend.reports.html_report import generate_html_report
from backend.reports.json_csv_report import generate_json_report, generate_csv_report


class MockFile:
    def __init__(self, filename, filepath, language="python"):
        self.filename = filename
        self.filepath = filepath
        self.language = language


class MockProject:
    def __init__(self, name="SentinelAI Web Service", files=None):
        import uuid
        self.id = uuid.uuid4()
        self.project_name = name
        self.files = files or []
        self.scan_date = datetime(2026, 9, 28, 14, 30, tzinfo=timezone.utc)


class MockScan:
    def __init__(self):
        import uuid
        self.id = uuid.uuid4()
        self.scan_time = datetime(2026, 9, 28, 14, 30, tzinfo=timezone.utc)
        self.critical_count = 2
        self.high_count = 1
        self.medium_count = 2
        self.low_count = 1
        self.total_issues = 7
        self.status = "completed"


class MockVuln:
    def __init__(
        self,
        v_type,
        severity,
        line_number,
        file_obj,
        description,
        recommendation=None,
        code_snippet=None,
        suggested_fix=None,
        cwe_id=None,
        owasp_category=None,
        fixed=False,
        auto_fixable=True,
    ):
        import uuid
        self.id = uuid.uuid4()
        self.type = v_type
        self.severity = severity
        self.line_number = line_number
        self.file = file_obj
        self.description = description
        self.recommendation = recommendation
        self.code_snippet = code_snippet
        self.suggested_fix = suggested_fix
        self.cwe_id = cwe_id
        self.owasp_category = owasp_category
        self.fixed = fixed
        self.auto_fixable = auto_fixable
        self.confidence = 0.95
        self.source_tool = "semgrep"


def test_pdf_report_mixed_findings():
    f1 = MockFile("auth_service.py", "backend/services/auth_service.py", "python")
    f2 = MockFile("api_routes.py", "backend/routes/api_routes.py", "python")
    f3 = MockFile("config.py", "backend/config.py", "python")
    proj = MockProject("SentinelAI Core Platform", [f1, f2, f3])
    scan = MockScan()

    vulns_7 = [
        MockVuln("SQL Injection", "critical", 42, f1, "### SQLi\nUnsanitized input.", "Use ORM.", "query = f'SELECT {u}'", "query = :u", "CWE-89", "A03:2021-Injection"),
        MockVuln("Hardcoded Secret", "critical", 15, f3, "Hardcoded secret.", "Use env var.", "KEY = '123'", "KEY = os.getenv('KEY')", "CWE-798", None),
        MockVuln("RCE Pickle", "high", 88, f2, "Pickle deserialize.", "Use json.", "pickle.loads()", "json.loads()", "CWE-502", "A08:2021"),
        MockVuln("XSS Reflected", "medium", 104, f2, "Reflected string.", "Sanitize.", "render(user_input)", "render(escape(user_input))", "CWE-79", "A03:2021", fixed=True),
        MockVuln("CORS Wildcard", "medium", 22, f2, "Insecure CORS.", "Whitelist origin.", "origin = '*'", "origin = 'app.com'"),
        MockVuln("Missing CSP", "low", 5, f2, "Missing headers.", "Add CSP middleware.", "pass", "app.add_headers()"),
        MockVuln("Verbose Error", "info", 210, f1, "Traceback returned.", "Log internally.", "return str(e)", "return 'error'"),
    ]

    score = _calc_score(vulns_7)
    assert score == 55

    pdf_bytes = generate_pdf_report_for_project(proj, scan, vulns_7)
    assert pdf_bytes is not None
    assert len(pdf_bytes) > 5000

    reader = pypdf.PdfReader(os.io.BytesIO(pdf_bytes) if hasattr(os, "io") else __import__("io").BytesIO(pdf_bytes))
    assert len(reader.pages) >= 1
    text = "\n".join([p.extract_text() for p in reader.pages])
    assert "SentinelAI" in text
    assert "Security Score" in text.title()
    assert "55" in text


def test_pdf_report_empty_state():
    f1 = MockFile("clean.py", "backend/clean.py", "python")
    proj = MockProject("Clean App", [f1])
    scan = MockScan()

    assert _calc_score([]) == 100

    pdf_bytes = generate_pdf_report_for_project(proj, scan, [])
    assert pdf_bytes is not None
    reader = pypdf.PdfReader(__import__("io").BytesIO(pdf_bytes))
    text = "\n".join([p.extract_text() for p in reader.pages])
    assert "No vulnerabilities found" in text
    assert "100" in text


def test_pdf_report_xss_and_long_lines():
    f1 = MockFile("xss.py", "backend/xss.py", "python")
    proj = MockProject("XSS Test", [f1])
    scan = MockScan()

    xss_snippet = "<script>alert('pwned' & \"attack\");</script>\n" + "x = '" + ("A" * 140) + "'\n" + "\n".join([f"line_{i} = {i}" for i in range(70)])
    vulns = [
        MockVuln(
            "XSS & Special Chars",
            "critical",
            10,
            f1,
            "Description with <script>, &, \", and `code()`.",
            "Recommendation with **bold**.",
            xss_snippet,
            "x = safe",
            "CWE-79",
            "A03:2021",
        )
    ]

    pdf_bytes = generate_pdf_report_for_project(proj, scan, vulns)
    assert pdf_bytes is not None
    reader = pypdf.PdfReader(__import__("io").BytesIO(pdf_bytes))
    text = "\n".join([p.extract_text() for p in reader.pages])
    assert "<script>alert" in text or "alert('pwned'" in text
    assert "[truncated]" in text


def test_pdf_report_large_volume():
    f1 = MockFile("large.py", "backend/large.py", "python")
    proj = MockProject("Large Scan", [f1])
    scan = MockScan()

    vulns = []
    severities = ["critical", "high", "medium", "low", "info"]
    for i in range(105):
        s = severities[i % 5]
        vulns.append(
            MockVuln(f"Issue {i}", s, i + 1, f1, f"Desc {i}", f"Fix {i}", f"code_{i}()", f"safe_{i}()")
        )

    t0 = time.time()
    pdf_bytes = generate_pdf_report_for_project(proj, scan, vulns)
    dur = time.time() - t0
    assert pdf_bytes is not None
    assert dur < 15.0
    reader = pypdf.PdfReader(__import__("io").BytesIO(pdf_bytes))
    assert len(reader.pages) > 10


def test_other_export_formats_unchanged():
    f1 = MockFile("test.py", "backend/test.py", "python")
    proj = MockProject("Exports Test", [f1])
    scan = MockScan()
    vulns = [
        MockVuln("SQL Injection", "critical", 10, f1, "SQLi issue", "Fix SQLi", "SELECT", "SELECT param")
    ]

    html = generate_html_report(proj, scan, vulns)
    assert "<!DOCTYPE html>" in html

    json_str = generate_json_report(proj, scan, vulns)
    assert '"project_name": "Exports Test"' in json_str

    csv_str = generate_csv_report(vulns)
    assert "Vulnerability ID,File Path,Line Number" in csv_str
