import json
import uuid
from datetime import datetime, timezone
import pytest
from unittest.mock import MagicMock, patch
import concurrent.futures

from backend.models.schemas import ScanHistoryOut
from backend.detectors.orchestrator import Orchestrator
from backend.reports.pdf_report import generate_pdf_html


def test_scan_history_out_normal_scan():
    """A scan where bandit, ast, and semgrep all ran is complete."""
    scan = ScanHistoryOut(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        scan_time=datetime.now(timezone.utc),
        total_issues=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        status="completed",
        engines_run=["bandit", "ast", "semgrep", "osv"]
    )
    assert scan.incomplete is False


def test_scan_history_out_all_engines_timed_out():
    """A scan where bandit, ast, and semgrep all timed out is incomplete."""
    scan = ScanHistoryOut(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        scan_time=datetime.now(timezone.utc),
        total_issues=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        status="completed",
        engines_run=["osv"]
    )
    assert scan.incomplete is True


def test_scan_history_out_partial_engine_timeout():
    """A scan missing semgrep or bandit is incomplete."""
    scan1 = ScanHistoryOut(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        scan_time=datetime.now(timezone.utc),
        total_issues=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        status="completed",
        engines_run=["bandit", "ast"]
    )
    assert scan1.incomplete is True

    scan2 = ScanHistoryOut(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        scan_time=datetime.now(timezone.utc),
        total_issues=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        status="completed",
        engines_run=None
    )
    assert scan2.incomplete is True


def test_pdf_report_normal_vs_incomplete():
    """PDF report displays calculated score for normal scans and '—' with warning banner for incomplete scans."""
    project = MagicMock()
    project.name = "TestProject"
    project.files = []

    # Normal scan
    normal_scan = MagicMock()
    normal_scan.scan_time = datetime.now(timezone.utc)
    normal_scan.engines_run = ["bandit", "ast", "semgrep"]
    normal_html = generate_pdf_html(project, normal_scan, [])
    assert '<div class="score-num" style="color: #16a34a;">100</div>' in normal_html
    assert "Incomplete scan: not a security assessment" not in normal_html

    # Incomplete scan (timed out engines)
    incomplete_scan = MagicMock()
    incomplete_scan.scan_time = datetime.now(timezone.utc)
    incomplete_scan.engines_run = ["osv"]
    incomplete_html = generate_pdf_html(project, incomplete_scan, [])
    assert '<div class="score-num" style="color: #ca8a04;">—</div>' in incomplete_html
    assert "Incomplete scan: not a security assessment" in incomplete_html


def test_orchestrator_all_engines_timeout(tmp_path):
    """When all engines time out, orchestrator adds warnings and leaves engines_run without them."""
    # Create sample python file so engines are triggered
    py_file = tmp_path / "app.py"
    py_file.write_text("x = 1\n", encoding="utf-8")

    orchestrator = Orchestrator()

    # Mock detectors to time out
    def slow_scan(*args, **kwargs):
        raise concurrent.futures.TimeoutError("timed out")

    with patch.object(orchestrator.bandit, "scan", side_effect=slow_scan), \
         patch.object(orchestrator.ast, "scan", side_effect=slow_scan), \
         patch.object(orchestrator.semgrep, "scan", side_effect=slow_scan):

        findings = orchestrator.scan_project(str(tmp_path), engine_timeout=1)

        assert "bandit" not in orchestrator.engines_run
        assert "ast" not in orchestrator.engines_run
        assert "semgrep" not in orchestrator.engines_run
        assert any("Engine 'bandit' timed out" in w for w in orchestrator.warnings)
        assert any("Engine 'ast' timed out" in w for w in orchestrator.warnings)
        assert any("Engine 'semgrep' timed out" in w for w in orchestrator.warnings)
